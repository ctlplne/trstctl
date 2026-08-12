// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/audit"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/revocationhealth"
	"trstctl.com/trstctl/internal/store"
)

// privacyDiscoveryRunQueued is the closed union carried by
// discovery.run.queued. The projector reads the embedded common relay fields;
// AD CS boot reconciliation additionally needs its immutable public connection
// command. PasswordRef is a reference name, never credential material.
type privacyDiscoveryRunQueued struct {
	segmentscan.Intent
	URL                string `json:"url,omitempty"`
	ConfigurationDN    string `json:"configuration_dn,omitempty"`
	BindDN             string `json:"bind_dn,omitempty"`
	PasswordRef        string `json:"password_ref,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

func privacyRules(rules ...events.PrivacyFieldRule) events.PrivacyEventPolicy {
	return events.PrivacyEventPolicy{Rules: rules}
}

func privacyRule(path string, mode events.PrivacyFieldMode) events.PrivacyFieldRule {
	return events.PrivacyFieldRule{Path: path, Mode: mode}
}

// exactProjectorPrivacyPolicies contains only full paths for the exact decoded
// schema. Payload structs that are byte-identical intentionally reuse a policy;
// all other known schemas receive an explicit reject-all policy below. That safe
// default can make an erasure stop, but it cannot silently preserve PII or mutate
// an authority field when a new decoder path was not classified.
func exactProjectorPrivacyPolicies() map[privacyEventPolicyKey]events.PrivacyEventPolicy {
	const (
		exact  = events.PrivacyFieldIdentityExact
		token  = events.PrivacyFieldSubjectToken
		clear  = events.PrivacyFieldFreeTextClear
		jsonID = events.PrivacyFieldJSONIdentityValues
		opaque = events.PrivacyFieldOpaqueExact
	)
	owner := privacyRules(
		privacyRule("/id", opaque), privacyRule("/kind", opaque),
		privacyRule("/name", token), privacyRule("/email", exact),
	)
	approvalRequested := privacyRules(
		privacyRule("/id", opaque), privacyRule("/intent_digest", opaque),
		privacyRule("/resource_kind", opaque), privacyRule("/resource_id", opaque),
		privacyRule("/resource_name", token), privacyRule("/action", opaque),
		privacyRule("/requester", exact), privacyRule("/from_state", opaque),
		privacyRule("/to_state", opaque), privacyRule("/target_version", opaque),
		privacyRule("/reason", clear), privacyRule("/evidence_refs", clear),
		privacyRule("/required_approvals", opaque), privacyRule("/created_at", opaque),
		privacyRule("/expires_at", opaque),
	)
	approvalDecision := privacyRules(
		privacyRule("/request_id", opaque), privacyRule("/intent_digest", opaque),
		privacyRule("/approver", exact), privacyRule("/decision", opaque),
		privacyRule("/reason", clear), privacyRule("/decided_at", opaque),
		privacyRule("/expected_resource_kind", opaque),
		privacyRule("/expected_resource_id", opaque),
		privacyRule("/expected_action", opaque),
	)
	approvalStatus := privacyRules(
		privacyRule("/request_id", opaque), privacyRule("/intent_digest", opaque),
		privacyRule("/status", opaque), privacyRule("/changed_at", opaque),
		privacyRule("/replacement_id", opaque),
	)
	tenantMember := privacyRules(
		privacyRule("/subject", exact), privacyRule("/display_name", token),
		privacyRule("/email", exact), privacyRule("/roles", opaque),
		privacyRule("/source", opaque),
	)
	ownerDeleted := privacyRules(privacyRule("/id", opaque))
	privacyErasedV1 := privacyRules(
		privacyRule("/subject_ref", opaque), privacyRule("/requested_by_ref", opaque),
		privacyRule("/reason", clear), privacyRule("/selectors", opaque),
		privacyRule("/counts", opaque),
	)
	privacyErasedV2 := privacyRules(
		privacyRule("/operation_id", opaque), privacyRule("/request_binding", opaque),
		privacyRule("/subject_ref", opaque), privacyRule("/requested_by_ref", opaque),
		privacyRule("/reason", clear), privacyRule("/selectors", opaque),
		privacyRule("/counts", opaque),
	)
	privacyErasedV3 := privacyRules(
		privacyRule("/operation_id", opaque), privacyRule("/request_binding", opaque),
		privacyRule("/subject_ref", opaque), privacyRule("/requested_by_ref", opaque),
		privacyRule("/reason", clear), privacyRule("/selectors", opaque),
		privacyRule("/counts", opaque), privacyRule("/recovery_fences", opaque),
	)
	certificateRevoked := privacyRules(
		privacyRule("/fingerprint", opaque), privacyRule("/ca_id", opaque),
		privacyRule("/serial", opaque), privacyRule("/reason", clear),
		privacyRule("/reason_code", opaque), privacyRule("/revoked_at", opaque),
	)
	certificateRecorded := privacyRules(
		privacyRule("/id", opaque), privacyRule("/ca_id", opaque),
		privacyRule("/owner_id", opaque), privacyRule("/subject", token),
		privacyRule("/sans/*", token), privacyRule("/issuer", opaque),
		privacyRule("/serial", opaque), privacyRule("/fingerprint", opaque),
		privacyRule("/key_algorithm", opaque), privacyRule("/not_before", opaque),
		privacyRule("/not_after", opaque), privacyRule("/deployment_location", opaque),
		privacyRule("/source", opaque), privacyRule("/replaces_id", opaque),
		privacyRule("/certificate_der", opaque), privacyRule("/certificate_pem", opaque),
		privacyRule("/issuance_response", opaque), privacyRule("/issuance_idempotency_key", opaque),
		privacyRule("/issuance_request_binding", opaque), privacyRule("/key_origin", opaque),
		privacyRule("/key_storage", opaque), privacyRule("/key_exportable", opaque),
		privacyRule("/key_generated_by", opaque),
	)
	approvedCertificate := certificateRecorded
	approvedCertificate.Rules = append(append([]events.PrivacyFieldRule{}, certificateRecorded.Rules...),
		privacyRule("/approval/request_id", opaque),
		privacyRule("/approval/intent_digest", opaque),
		privacyRule("/approval/requester", exact),
		privacyRule("/approval/resource_kind", opaque),
		privacyRule("/approval/resource_id", opaque),
		privacyRule("/approval/action", opaque),
		privacyRule("/approval/from_state", opaque),
		privacyRule("/approval/to_state", opaque),
		privacyRule("/approval/target_version", opaque),
		privacyRule("/approval/required_approvals", opaque),
		privacyRule("/approval/reason", clear),
		privacyRule("/approval/evidence_refs", clear),
		privacyRule("/approval/issuance", opaque),
		privacyRule("/approval_binding", opaque),
	)
	issuanceRequestOpened := privacyRules(
		privacyRule("/id", opaque), privacyRule("/subject", token),
		privacyRule("/profile", opaque), privacyRule("/csr_pem", opaque),
		privacyRule("/requester", exact), privacyRule("/justification", clear),
		privacyRule("/origin", opaque), privacyRule("/ticket_ref", opaque),
		privacyRule("/expires_at", opaque),
	)
	issuanceRequestDecided := privacyRules(
		privacyRule("/id", opaque), privacyRule("/status", opaque),
		privacyRule("/decided_by", exact), privacyRule("/reason", clear),
		privacyRule("/identity_id", opaque), privacyRule("/decided_at", opaque),
	)
	identityCreated := privacyRules(
		privacyRule("/id", opaque), privacyRule("/kind", opaque),
		privacyRule("/name", token), privacyRule("/owner_id", opaque),
		privacyRule("/issuer_id", opaque), privacyRule("/attributes", clear),
	)
	identityTransitionV1 := privacyRules(
		privacyRule("/identity_id", opaque), privacyRule("/from", opaque),
		privacyRule("/to", opaque), privacyRule("/reason", clear),
	)
	identityTransitionV2 := privacyRules(
		privacyRule("/identity_id", opaque), privacyRule("/from", opaque),
		privacyRule("/to", opaque), privacyRule("/reason", clear),
		privacyRule("/idempotency_key", opaque),
	)
	identityTransitionV3 := privacyRules(
		privacyRule("/identity_id", opaque), privacyRule("/from", opaque),
		privacyRule("/to", opaque), privacyRule("/reason", clear),
		privacyRule("/idempotency_key", opaque), privacyRule("/subject_csr_pem", opaque),
		privacyRule("/side_effect/destination", opaque),
		privacyRule("/side_effect/idempotency_key", opaque),
		privacyRule("/side_effect/payload", opaque),
		privacyRule("/side_effect/required_agent_role", opaque),
	)
	identityTransitionV4 := privacyRules(
		privacyRule("/identity_id", opaque), privacyRule("/from", opaque),
		privacyRule("/to", opaque), privacyRule("/reason", clear),
		privacyRule("/idempotency_key", opaque), privacyRule("/subject_csr_pem", opaque),
		privacyRule("/side_effect/destination", opaque),
		privacyRule("/side_effect/idempotency_key", opaque),
		privacyRule("/side_effect/payload", opaque),
		privacyRule("/side_effect/required_agent_role", opaque),
		privacyRule("/approval/request_id", opaque),
		privacyRule("/approval/intent_digest", opaque),
		privacyRule("/approval/requester", exact),
		privacyRule("/approval/resource_kind", opaque),
		privacyRule("/approval/resource_id", opaque),
		privacyRule("/approval/action", opaque),
		privacyRule("/approval/from_state", opaque),
		privacyRule("/approval/to_state", opaque),
		privacyRule("/approval/target_version", opaque),
		privacyRule("/approval/required_approvals", opaque),
		privacyRule("/approval/reason", clear),
		privacyRule("/approval/evidence_refs/*", clear),
		privacyRule("/approval/issuance/profile_name", opaque),
		privacyRule("/approval/issuance/profile_id", opaque),
		privacyRule("/approval/issuance/profile_version", opaque),
		privacyRule("/approval/issuance/profile_spec_digest", opaque),
		privacyRule("/approval/issuance/requested_ttl_seconds", opaque),
		privacyRule("/approval/issuance/effective_ttl_seconds", opaque),
	)
	identityTransitionV5 := privacyRules(
		privacyRule("/identity_id", opaque), privacyRule("/from", opaque),
		privacyRule("/to", opaque), privacyRule("/reason", clear),
		privacyRule("/idempotency_key", opaque), privacyRule("/subject_csr_pem", opaque),
		privacyRule("/side_effect/destination", opaque),
		privacyRule("/side_effect/idempotency_key", opaque),
		privacyRule("/side_effect/payload", opaque),
		privacyRule("/side_effect/required_agent_role", opaque),
		privacyRule("/issuance/profile_name", opaque),
		privacyRule("/issuance/profile_id", opaque),
		privacyRule("/issuance/profile_version", opaque),
		privacyRule("/issuance/profile_spec_digest", opaque),
		privacyRule("/issuance/requested_ttl_seconds", opaque),
		privacyRule("/issuance/effective_ttl_seconds", opaque),
	)
	agentHeartbeat := privacyRules(
		privacyRule("/id", opaque), privacyRule("/agent", exact),
		privacyRule("/version", opaque), privacyRule("/status", opaque),
		privacyRule("/cert_serial", opaque), privacyRule("/roles", opaque),
		privacyRule("/workload_api_served", opaque),
		privacyRule("/workload_api_svids", opaque),
	)
	agentCertRenewed := privacyRules(
		privacyRule("/id", opaque), privacyRule("/agent", exact),
		privacyRule("/old_serial", opaque), privacyRule("/new_serial", opaque),
	)
	agentCertRevoked := privacyRules(
		privacyRule("/id", opaque), privacyRule("/agent", exact),
		privacyRule("/serial", opaque), privacyRule("/fingerprint", opaque),
		privacyRule("/reason", clear), privacyRule("/revoked_at", opaque),
	)
	agentOffboarded := privacyRules(
		privacyRule("/id", opaque), privacyRule("/agent", exact),
		privacyRule("/reason", clear), privacyRule("/offboarded_by", exact),
	)
	profileV2 := privacyRules(
		privacyRule("/id", opaque), privacyRule("/name", opaque),
		privacyRule("/version", opaque), privacyRule("/spec", opaque),
		privacyRule("/active", opaque), privacyRule("/created_by", exact),
	)
	discoverySource := privacyRules(
		privacyRule("/id", opaque), privacyRule("/kind", opaque),
		privacyRule("/name", opaque), privacyRule("/config", jsonID),
	)
	discoverySegment := privacyRules(
		privacyRule("/id", opaque), privacyRule("/name", token),
		privacyRule("/ranges", opaque), privacyRule("/staleness_hours", opaque),
		privacyRule("/excluded", opaque), privacyRule("/exclusion_reason", clear),
	)
	discoveryRunQueued := privacyRules(
		privacyRule("/id", opaque), privacyRule("/source_id", opaque),
		privacyRule("/job_kind", opaque),
		privacyRule("/schedule_id", opaque), privacyRule("/dry_run", opaque),
		privacyRule("/requested_by", exact),
		privacyRule("/execution", opaque), privacyRule("/mode", opaque),
		privacyRule("/targets", opaque), privacyRule("/allow_rfc1918", opaque),
		privacyRule("/allow_loopback", opaque), privacyRule("/allow_reserved_ranges", opaque),
		privacyRule("/segment", opaque), privacyRule("/required_agent_role", opaque),
		privacyRule("/required_agent_id", opaque), privacyRule("/url", opaque),
		privacyRule("/configuration_dn", token), privacyRule("/bind_dn", token),
		privacyRule("/password_ref", token), privacyRule("/insecure_skip_verify", opaque),
	)
	discoveryFinding := privacyRules(
		privacyRule("/id", opaque), privacyRule("/run_id", opaque),
		privacyRule("/source_id", opaque), privacyRule("/kind", opaque),
		privacyRule("/ref", opaque), privacyRule("/provenance", opaque),
		privacyRule("/fingerprint", opaque), privacyRule("/risk_score", opaque),
		privacyRule("/metadata", jsonID),
	)
	discoveryTriage := privacyRules(
		privacyRule("/id", opaque), privacyRule("/status", opaque),
		privacyRule("/managed_identity_id", opaque), privacyRule("/actor", exact),
		privacyRule("/reason", clear), privacyRule("/metadata_patch", jsonID),
	)
	apiTokenCreated := privacyRules(
		privacyRule("/id", opaque), privacyRule("/token_hash", opaque),
		privacyRule("/subject", exact), privacyRule("/scopes", opaque),
		privacyRule("/expires_at", opaque),
	)
	apiTokenRevoked := privacyRules(
		privacyRule("/id", opaque), privacyRule("/reason", clear),
		privacyRule("/revoked_by", exact),
	)
	pamSessionStarted := privacyRules(
		privacyRule("/id", opaque), privacyRule("/target_type", opaque),
		privacyRule("/target_id", opaque), privacyRule("/role", opaque),
		privacyRule("/status", opaque), privacyRule("/subject", exact),
		privacyRule("/requested_by", exact), privacyRule("/reason", clear),
		privacyRule("/attestation_id", opaque), privacyRule("/backend_ref", opaque),
		privacyRule("/ssh_key_id", opaque), privacyRule("/ssh_serial", opaque),
		privacyRule("/idempotency_key", opaque), privacyRule("/audit", clear),
		privacyRule("/started_at", opaque), privacyRule("/expires_at", opaque),
	)
	pamSessionExpired := privacyRules(
		privacyRule("/id", opaque), privacyRule("/ended_at", opaque),
		privacyRule("/reason", clear),
	)
	accessReviewCampaign := privacyRules(
		privacyRule("/id", opaque), privacyRule("/name", opaque),
		privacyRule("/scope", opaque), privacyRule("/reviewer_subject", exact),
		privacyRule("/requested_by", exact), privacyRule("/due_at", opaque),
		privacyRule("/items", opaque),
	)
	accessReviewDecision := privacyRules(
		privacyRule("/campaign_id", opaque), privacyRule("/item_id", opaque),
		privacyRule("/decision", opaque), privacyRule("/reviewer_subject", exact),
		privacyRule("/reason", clear), privacyRule("/decision_evidence_refs/*", clear),
		privacyRule("/decided_at", opaque),
	)
	accessChangeRequest := privacyRules(
		privacyRule("/id", opaque), privacyRule("/requested_action", opaque),
		privacyRule("/requester_subject", exact), privacyRule("/nhi_id", opaque),
		privacyRule("/nhi_kind", opaque), privacyRule("/display_name", opaque),
		privacyRule("/owner_ref", opaque), privacyRule("/resource", opaque),
		privacyRule("/entitlement", opaque), privacyRule("/change_ref", opaque),
		privacyRule("/change_system", opaque), privacyRule("/change_url", opaque),
		privacyRule("/risk", opaque), privacyRule("/reason", clear),
		privacyRule("/evidence_refs/*", clear), privacyRule("/required_approvals", opaque),
	)
	accessChangeDecision := privacyRules(
		privacyRule("/request_id", opaque), privacyRule("/decision", opaque),
		privacyRule("/approver_subject", exact), privacyRule("/reason", clear),
		privacyRule("/decision_evidence_refs/*", clear), privacyRule("/decided_at", opaque),
	)
	complianceSchedule := privacyRules(
		privacyRule("/id", opaque), privacyRule("/framework", opaque),
		privacyRule("/name", opaque), privacyRule("/report_type", opaque),
		privacyRule("/interval_seconds", opaque), privacyRule("/enabled", opaque),
		privacyRule("/delivery", opaque), privacyRule("/recipient_ref", exact),
	)
	secretRotationRunV1 := privacyRules(
		privacyRule("/schedule_id", opaque), privacyRule("/run_id", opaque),
		privacyRule("/status", opaque), privacyRule("/new_ref", opaque),
		privacyRule("/error", clear),
	)
	secretRotationRunV2 := privacyRules(
		privacyRule("/schedule_id", opaque), privacyRule("/run_id", opaque),
		privacyRule("/due_at", opaque), privacyRule("/provider", token),
		privacyRule("/key", token), privacyRule("/old_ref", opaque),
		privacyRule("/interval_seconds", opaque),
		privacyRule("/config_event_sequence", opaque),
		privacyRule("/command_key", opaque), privacyRule("/request_binding", opaque),
		privacyRule("/status", opaque), privacyRule("/new_ref", opaque),
		privacyRule("/error", clear),
	)
	secretRotationRunV3 := secretRotationRunV2
	secretRotationRunV3.Rules = append(append([]events.PrivacyFieldRule{}, secretRotationRunV2.Rules...),
		privacyRule("/tenant_registration_event_id", opaque),
		privacyRule("/tenant_registration_event_sequence", opaque),
	)
	notificationThreshold := privacyRules(
		privacyRule("/subject", exact), privacyRule("/threshold_days", opaque),
		privacyRule("/channel", exact), privacyRule("/sent_at", opaque),
	)
	notificationRouting := privacyRules(
		privacyRule("/id", opaque), privacyRule("/name", opaque),
		privacyRule("/channels_by_severity", opaque), privacyRule("/default_channels", opaque),
		privacyRule("/owner_ref", exact), privacyRule("/owner_email", clear),
		privacyRule("/digest_interval_seconds", opaque),
		privacyRule("/digest_timezone", opaque),
	)
	incidentExecution := privacyRules(
		privacyRule("/id", opaque), privacyRule("/compromised_identity_id", opaque),
		privacyRule("/replacement_identity_id", opaque),
		privacyRule("/connector_delivery_id", opaque), privacyRule("/status", opaque),
		privacyRule("/phase", opaque), privacyRule("/reason", clear),
		privacyRule("/blast_radius", opaque), privacyRule("/revocation_status", opaque),
		privacyRule("/evidence_bundle_format", opaque),
		privacyRule("/evidence_bundle", clear), privacyRule("/failed_targets/*", clear),
		privacyRule("/rollback_refs/*", clear), privacyRule("/idempotency_key", opaque),
		privacyRule("/created_by", exact),
	)
	incidentFleet := privacyRules(
		privacyRule("/id", opaque), privacyRule("/issuer_id", opaque),
		privacyRule("/status", opaque), privacyRule("/phase", opaque),
		privacyRule("/reason", clear), privacyRule("/batch_size", opaque),
		privacyRule("/next_batch_index", opaque), privacyRule("/halted_reason", clear),
		privacyRule("/connector", opaque), privacyRule("/target", opaque),
		privacyRule("/graph_impact", opaque), privacyRule("/affected_identity_ids", opaque),
		privacyRule("/replacement_identity_ids", opaque),
		privacyRule("/revoked_identity_ids", opaque),
		privacyRule("/connector_delivery_ids", opaque), privacyRule("/batches", opaque),
		privacyRule("/health_gates", opaque), privacyRule("/failed_targets/*", clear),
		privacyRule("/rollback_refs/*", clear),
		privacyRule("/evidence_bundle_format", opaque),
		privacyRule("/evidence_bundle", clear), privacyRule("/idempotency_key", opaque),
		privacyRule("/created_by", exact),
	)
	remediationRun := privacyRules(
		privacyRule("/id", opaque), privacyRule("/playbook_id", opaque),
		privacyRule("/target_identity_id", opaque), privacyRule("/inventory_id", opaque),
		privacyRule("/status", opaque), privacyRule("/phase", opaque),
		privacyRule("/action", opaque), privacyRule("/reason", clear),
		privacyRule("/connector", opaque), privacyRule("/target", opaque),
		privacyRule("/outbox_id", opaque), privacyRule("/connector_delivery_id", opaque),
		privacyRule("/scope_delta", opaque), privacyRule("/evidence_refs/*", clear),
		privacyRule("/rollback_refs/*", clear), privacyRule("/idempotency_key", opaque),
		privacyRule("/request_binding", opaque), privacyRule("/initial_http_status", opaque),
		privacyRule("/initial_response", clear), privacyRule("/terminal_reason", clear),
		privacyRule("/outbox_idempotency_key", opaque), privacyRule("/created_by", exact),
	)
	revocationTargets := []events.PrivacyFieldRule{
		privacyRule("/targets/*/key", opaque), privacyRule("/targets/*/protocol", opaque),
		privacyRule("/targets/*/endpoint", opaque), privacyRule("/targets/*/issuer_subject", token),
		privacyRule("/targets/*/issuer_fingerprint", opaque), privacyRule("/targets/*/issuer_der", opaque),
		privacyRule("/targets/*/certificate_id", opaque), privacyRule("/targets/*/certificate_subject", token),
		privacyRule("/targets/*/certificate_fingerprint", opaque), privacyRule("/targets/*/certificate_serial", opaque),
		privacyRule("/targets/*/certificate_der", opaque),
	}
	revocationProbe := privacyRules(
		privacyRule("/id", opaque), privacyRule("/bucket", opaque),
		privacyRule("/batch_index", opaque), privacyRule("/batch_count", opaque),
		privacyRule("/stale_within_seconds", opaque), privacyRule("/required_agent_role", opaque),
		privacyRule("/required_agent_id", opaque), privacyRule("/endpoints/*", opaque),
		privacyRule("/issuer_der", opaque),
	)
	revocationProbe.Rules = append(revocationProbe.Rules, revocationTargets...)
	revocationObserved := privacyRules(
		privacyRule("/probe_id", opaque), privacyRule("/bucket", opaque),
		privacyRule("/batch_index", opaque), privacyRule("/batch_count", opaque),
		privacyRule("/agent_id", opaque), privacyRule("/agent_name", token),
		privacyRule("/evidence_digest", opaque),
		privacyRule("/findings/*/target_key", opaque), privacyRule("/findings/*/protocol", opaque),
		privacyRule("/findings/*/endpoint", opaque), privacyRule("/findings/*/status", opaque),
		privacyRule("/findings/*/detail_code", opaque), privacyRule("/findings/*/detail", clear),
		privacyRule("/findings/*/latency_ms", opaque), privacyRule("/findings/*/this_update", opaque),
		privacyRule("/findings/*/next_update", opaque), privacyRule("/findings/*/signature_verified", opaque),
		privacyRule("/findings/*/revoked_count", opaque), privacyRule("/findings/*/response_status", opaque),
		privacyRule("/findings/*/responder_subject", token),
	)
	revocationObserved.Rules = append(revocationObserved.Rules, revocationTargets...)
	migrationRun := privacyRules(
		privacyRule("/run/id", opaque), privacyRule("/run/plan_id", token),
		privacyRule("/run/status", opaque), privacyRule("/run/halt_reason", clear),
		privacyRule("/run/rollback_wave_id", token), privacyRule("/run/rollback_stage", opaque),
		privacyRule("/run/rollback_attempt", opaque), privacyRule("/run/pause_reason", clear),
		privacyRule("/run/waves/*/id", token), privacyRule("/run/waves/*/ordinal", opaque),
		privacyRule("/run/waves/*/phase", opaque), privacyRule("/run/waves/*/started", opaque),
		privacyRule("/run/waves/*/halt_reason", clear),
		privacyRule("/run/waves/*/members/*/identity_id", opaque),
		privacyRule("/run/waves/*/members/*/trust_verdict", opaque),
		privacyRule("/run/waves/*/members/*/successor_verdict", opaque),
		privacyRule("/run/waves/*/members/*/rollback_successor_verdict", opaque),
		privacyRule("/run/waves/*/members/*/rollback_trust_verdict", opaque),
		privacyRule("/run/waves/*/members/*/binding/issuing_authority_id", opaque),
		privacyRule("/run/waves/*/members/*/binding/target_id", opaque),
		privacyRule("/run/waves/*/members/*/binding/target_revision", opaque),
		privacyRule("/run/waves/*/members/*/binding/connector", opaque),
		privacyRule("/run/waves/*/members/*/binding/target", token),
		privacyRule("/run/waves/*/members/*/binding/target_config", jsonID),
		privacyRule("/run/waves/*/members/*/binding/required_agent_id", opaque),
		privacyRule("/run/waves/*/members/*/binding/trust_anchor_path", token),
		privacyRule("/run/waves/*/members/*/binding/trust_anchor_pem", opaque),
		privacyRule("/run/waves/*/members/*/binding/trust_anchor_fingerprint", opaque),
		privacyRule("/run/waves/*/members/*/binding/verify_address", opaque),
		privacyRule("/run/waves/*/members/*/binding/verify_server_name", token),
		privacyRule("/run/waves/*/members/*/binding/subject_common_name", token),
		privacyRule("/run/waves/*/members/*/binding/subject_dns_names/*", token),
		privacyRule("/run/waves/*/members/*/binding/predecessor_certificate_id", opaque),
		privacyRule("/run/waves/*/members/*/binding/predecessor_fingerprint", opaque),
		privacyRule("/run/waves/*/members/*/binding/successor_fingerprint", opaque),
		privacyRule("/actions/*/kind", opaque), privacyRule("/actions/*/wave_id", token),
		privacyRule("/actions/*/identity_id", opaque),
	)
	policies := map[privacyEventPolicyKey]events.PrivacyEventPolicy{
		{EventOwnerCreated, 1}:             owner,
		{EventOwnerUpdated, 1}:             owner,
		{EventOwnerDeleted, 1}:             ownerDeleted,
		{EventApprovalRequested, 1}:        approvalRequested,
		{EventApprovalDecisionRecorded, 1}: approvalDecision,
		{EventApprovalStatusChanged, 1}:    approvalStatus,
		{EventIssuanceRequestOpened, 1}:    issuanceRequestOpened,
		{EventIssuanceRequestDecided, 1}:   issuanceRequestDecided,
		{EventIdentityCreated, 1}:          identityCreated,
		{EventTenantMemberUpserted, 1}:     tenantMember,
		{EventTenantMemberOffboarded, 1}: privacyRules(
			privacyRule("/subject", exact), privacyRule("/reason", clear),
			privacyRule("/offboarded_by", exact), privacyRule("/revoked_token_count", opaque),
		),
		{EventAPITokenCreated, 1}:   apiTokenCreated,
		{EventAPITokenRevoked, 1}:   apiTokenRevoked,
		{EventPAMSessionStarted, 1}: pamSessionStarted,
		{EventPAMSessionExpired, 1}: pamSessionExpired,
		{EventAgentHeartbeat, 1}:    agentHeartbeat,
		{EventAgentCertRenewed, 1}:  agentCertRenewed,
		{EventAgentCertRevoked, 1}:  agentCertRevoked,
		{EventAgentOffboarded, 1}:   agentOffboarded,
		{EventProfileCreated, 1}: privacyRules(
			privacyRule("/name", opaque), privacyRule("/version", opaque),
		),
		{EventProfileUpdated, 1}: privacyRules(
			privacyRule("/name", opaque), privacyRule("/version", opaque),
		),
		{EventProfileCreated, ProfileEventSchemaVersion}:                             profileV2,
		{EventProfileUpdated, ProfileEventSchemaVersion}:                             profileV2,
		{EventDiscoverySegmentUpserted, 1}:                                           discoverySegment,
		{EventDiscoverySourceUpserted, 1}:                                            discoverySource,
		{EventDiscoveryRunQueued, 1}:                                                 discoveryRunQueued,
		{EventRevocationProbeQueued, 1}:                                              revocationProbe,
		{EventRevocationHealthObserved, 1}:                                           revocationObserved,
		{EventMigrationRunRecorded, 1}:                                               migrationRun,
		{EventDiscoveryFindingRecorded, 1}:                                           discoveryFinding,
		{EventDiscoveryFindingTriageChanged, 1}:                                      discoveryTriage,
		{EventComplianceReportScheduleUpserted, 1}:                                   complianceSchedule,
		{EventSecretRotationScheduleRan, 1}:                                          secretRotationRunV1,
		{EventSecretRotationScheduleRan, 2}:                                          secretRotationRunV2,
		{EventSecretRotationScheduleRan, 3}:                                          secretRotationRunV3,
		{EventNotificationRoutingPolicyUpserted, 1}:                                  notificationRouting,
		{EventNotificationThresholdDelivered, 1}:                                     notificationThreshold,
		{EventIncidentExecutionRecorded, 1}:                                          incidentExecution,
		{EventIncidentFleetReissuanceRecorded, 1}:                                    incidentFleet,
		{EventRemediationPlaybookRunRecorded, 1}:                                     remediationRun,
		{EventNHIAccessReviewCampaignStarted, 1}:                                     accessReviewCampaign,
		{EventNHIAccessReviewItemDecided, 1}:                                         accessReviewDecision,
		{EventAccessChangeRequestCreated, 1}:                                         accessChangeRequest,
		{EventAccessChangeRequestDecided, 1}:                                         accessChangeDecision,
		{EventCertificateRevoked, 1}:                                                 certificateRevoked,
		{EventCertificateRecorded, 1}:                                                certificateRecorded,
		{EventCertificateRecorded, CertificateApprovalEventSchemaVersion}:            approvedCertificate,
		{EventPrivacySubjectErased, 1}:                                               privacyErasedV1,
		{EventPrivacySubjectErased, PrivacySubjectErasedOperationEventSchemaVersion}: privacyErasedV2,
		{EventPrivacySubjectErased, PrivacySubjectErasedEventSchemaVersion}:          privacyErasedV3,
		{EventPrivacyRetentionEnforced, 1}: privacyRules(
			privacyRule("/run_id", opaque), privacyRule("/requested_by_ref", opaque),
			privacyRule("/cutoffs", opaque), privacyRule("/counts", opaque),
		),
		{EventPrivacyArchiveErasureAttested, 1}: privacyRules(
			privacyRule("/attestation_id", opaque), privacyRule("/subject_ref", opaque),
			privacyRule("/requested_by_ref", opaque), privacyRule("/artifact_type", opaque),
			privacyRule("/artifact_uri", token), privacyRule("/action", opaque),
			privacyRule("/reason", clear), privacyRule("/evidence_refs", clear),
			privacyRule("/held_until", opaque),
		),
	}
	for _, eventType := range []string{
		EventIdentityIssued, EventIdentityDeployed, EventIdentityRevoked,
		EventIdentityRenewing, EventIdentityRenewed, EventIdentityRetired,
	} {
		policies[privacyEventPolicyKey{EventType: eventType, Version: 1}] = identityTransitionV1
		policies[privacyEventPolicyKey{EventType: eventType, Version: LifecycleEventSchemaVersion}] = identityTransitionV2
		policies[privacyEventPolicyKey{EventType: eventType, Version: LifecycleSideEffectEventSchemaVersion}] = identityTransitionV3
		policies[privacyEventPolicyKey{EventType: eventType, Version: LifecycleApprovalEventSchemaVersion}] = identityTransitionV4
	}
	policies[privacyEventPolicyKey{EventType: EventIdentityIssued, Version: LifecycleIssuanceEventSchemaVersion}] = identityTransitionV5
	return policies
}

type privacyEventPolicyKey struct {
	EventType string
	Version   int
}

type privacyProfileV1 struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

type privacySecretRotationRunV1 struct {
	ScheduleID string `json:"schedule_id"`
	RunID      string `json:"run_id"`
	Status     string `json:"status"`
	NewRef     string `json:"new_ref,omitempty"`
	Error      string `json:"error,omitempty"`
}

type privacySecretRotationRunV2 struct {
	ScheduleID          string    `json:"schedule_id"`
	RunID               string    `json:"run_id"`
	DueAt               time.Time `json:"due_at"`
	Provider            string    `json:"provider"`
	Key                 string    `json:"key"`
	OldRef              string    `json:"old_ref"`
	IntervalSeconds     int       `json:"interval_seconds"`
	ConfigEventSequence uint64    `json:"config_event_sequence"`
	CommandKey          string    `json:"command_key"`
	RequestBinding      string    `json:"request_binding"`
	Status              string    `json:"status"`
	NewRef              string    `json:"new_ref,omitempty"`
	Error               string    `json:"error,omitempty"`
}

type privacyDynamicSecretLegacyLeaseAudit struct {
	Lease      string `json:"lease"`
	Provider   string `json:"provider"`
	Role       string `json:"role"`
	BackendRef string `json:"backend_ref"`
	State      string `json:"state"`
}

// Dynamic-secret v1 shapes are kept explicit. The current Go payloads contain an
// optional epoch only so old bytes still decode; using those structs for v1
// privacy validation would accidentally bless tenant_epoch on the legacy schema.
type privacyDynamicSecretLeasePendingV1 struct {
	ID                string    `json:"id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	RequestBinding    string    `json:"request_binding,omitempty"`
	Provider          string    `json:"provider"`
	Role              string    `json:"role"`
	ExpiresAt         time.Time `json:"expires_at"`
	HardExpiresAt     time.Time `json:"hard_expires_at"`
	SealedPreparation []byte    `json:"sealed_preparation,omitempty"`
}

type privacyDynamicSecretLeasePreparedV1 struct {
	ID                string `json:"id"`
	Provider          string `json:"provider"`
	SealedPreparation []byte `json:"sealed_preparation"`
}

type privacyDynamicSecretLeaseIssuedV1 struct {
	ID               string    `json:"id"`
	IdempotencyKey   string    `json:"idempotency_key"`
	RequestBinding   string    `json:"request_binding,omitempty"`
	Provider         string    `json:"provider"`
	Role             string    `json:"role"`
	BackendRef       string    `json:"backend_ref"`
	SealedCredential []byte    `json:"sealed_credential"`
	ExpiresAt        time.Time `json:"expires_at"`
	HardExpiresAt    time.Time `json:"hard_expires_at"`
}

type privacyDynamicSecretLeaseFailureV1 struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

type privacyDynamicSecretLeaseRenewedV1 struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type privacyDynamicSecretLeaseRevocationRequestedV1 struct {
	ID         string `json:"id"`
	Provider   string `json:"provider"`
	BackendRef string `json:"backend_ref"`
}

type privacyDynamicSecretLeaseRevocationCompletedV1 struct {
	ID string `json:"id"`
}

type privacyDynamicSecretOperationRequestedV1 struct {
	OperationID    string          `json:"operation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	RequestBinding string          `json:"request_binding"`
	Action         string          `json:"action"`
	LeaseID        string          `json:"lease_id"`
	Response       json.RawMessage `json:"response"`
}

type privacyDynamicSecretOperationCompletedV1 struct {
	OperationID    string `json:"operation_id"`
	RequestBinding string `json:"request_binding"`
	Action         string `json:"action"`
	LeaseID        string `json:"lease_id"`
}

// Dynamic-secret v2 shapes deliberately make tenant_epoch (and the operation
// identity used by transition event IDs) required. Runtime payload structs keep
// those fields optional solely so retained v1 bytes can still be decoded.
type privacyDynamicSecretLeasePendingV2 struct {
	TenantEpoch       string    `json:"tenant_epoch"`
	ID                string    `json:"id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	RequestBinding    string    `json:"request_binding,omitempty"`
	Provider          string    `json:"provider"`
	Role              string    `json:"role"`
	ExpiresAt         time.Time `json:"expires_at"`
	HardExpiresAt     time.Time `json:"hard_expires_at"`
	SealedPreparation []byte    `json:"sealed_preparation,omitempty"`
}

type privacyDynamicSecretLeasePreparedV2 struct {
	TenantEpoch       string `json:"tenant_epoch"`
	ID                string `json:"id"`
	Provider          string `json:"provider"`
	SealedPreparation []byte `json:"sealed_preparation"`
}

type privacyDynamicSecretLeaseIssuedV2 struct {
	TenantEpoch      string    `json:"tenant_epoch"`
	ID               string    `json:"id"`
	IdempotencyKey   string    `json:"idempotency_key"`
	RequestBinding   string    `json:"request_binding,omitempty"`
	Provider         string    `json:"provider"`
	Role             string    `json:"role"`
	BackendRef       string    `json:"backend_ref"`
	SealedCredential []byte    `json:"sealed_credential"`
	ExpiresAt        time.Time `json:"expires_at"`
	HardExpiresAt    time.Time `json:"hard_expires_at"`
}

type privacyDynamicSecretLeaseFailureV2 struct {
	TenantEpoch string `json:"tenant_epoch"`
	ID          string `json:"id"`
	Error       string `json:"error"`
}

type privacyDynamicSecretLeaseRenewedV2 struct {
	TenantEpoch string    `json:"tenant_epoch"`
	OperationID string    `json:"operation_id"`
	ID          string    `json:"id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type privacyDynamicSecretLeaseRevocationRequestedV2 struct {
	TenantEpoch string `json:"tenant_epoch"`
	OperationID string `json:"operation_id"`
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	BackendRef  string `json:"backend_ref"`
}

type privacyDynamicSecretLeaseRevocationCompletedV2 struct {
	TenantEpoch string `json:"tenant_epoch"`
	ID          string `json:"id"`
}

type privacyDynamicSecretOperationRequestedV2 struct {
	TenantEpoch    string          `json:"tenant_epoch"`
	OperationID    string          `json:"operation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	RequestBinding string          `json:"request_binding"`
	Action         string          `json:"action"`
	LeaseID        string          `json:"lease_id"`
	Response       json.RawMessage `json:"response"`
}

type privacyDynamicSecretOperationCompletedV2 struct {
	TenantEpoch    string `json:"tenant_epoch"`
	OperationID    string `json:"operation_id"`
	RequestBinding string `json:"request_binding"`
	Action         string `json:"action"`
	LeaseID        string `json:"lease_id"`
}

type privacyCertificateRecordedV1 struct {
	ID                     string     `json:"id"`
	CAID                   string     `json:"ca_id,omitempty"`
	OwnerID                *string    `json:"owner_id"`
	Subject                string     `json:"subject"`
	SANs                   []string   `json:"sans"`
	Issuer                 string     `json:"issuer"`
	Serial                 string     `json:"serial"`
	Fingerprint            string     `json:"fingerprint"`
	KeyAlgorithm           string     `json:"key_algorithm"`
	NotBefore              *time.Time `json:"not_before"`
	NotAfter               *time.Time `json:"not_after"`
	DeploymentLocation     string     `json:"deployment_location"`
	Source                 string     `json:"source"`
	ReplacesID             *string    `json:"replaces_id,omitempty"`
	CertificateDER         []byte     `json:"certificate_der,omitempty"`
	CertificatePEM         []byte     `json:"certificate_pem,omitempty"`
	IssuanceResponse       []byte     `json:"issuance_response,omitempty"`
	IssuanceIdempotencyKey string     `json:"issuance_idempotency_key,omitempty"`
	IssuanceRequestBinding string     `json:"issuance_request_binding,omitempty"`
	KeyOrigin              string     `json:"key_origin,omitempty"`
	KeyStorage             string     `json:"key_storage,omitempty"`
	KeyExportable          string     `json:"key_exportable,omitempty"`
	KeyGeneratedBy         string     `json:"key_generated_by,omitempty"`
}

type privacySubjectErasedV1 struct {
	SubjectRef     string                        `json:"subject_ref"`
	RequestedByRef string                        `json:"requested_by_ref,omitempty"`
	Reason         string                        `json:"reason,omitempty"`
	Selectors      store.PrivacyErasureSelectors `json:"selectors"`
	Counts         map[string]int                `json:"counts,omitempty"`
}

type privacySubjectErasedV2 struct {
	OperationID    string                        `json:"operation_id"`
	RequestBinding string                        `json:"request_binding"`
	SubjectRef     string                        `json:"subject_ref"`
	RequestedByRef string                        `json:"requested_by_ref,omitempty"`
	Reason         string                        `json:"reason,omitempty"`
	Selectors      store.PrivacyErasureSelectors `json:"selectors"`
	Counts         map[string]int                `json:"counts,omitempty"`
}

type privacySubjectErasedV3 struct {
	OperationID           string                                           `json:"operation_id"`
	RequestBinding        string                                           `json:"request_binding"`
	SubjectRef            string                                           `json:"subject_ref"`
	RequestedByRef        string                                           `json:"requested_by_ref,omitempty"`
	Reason                string                                           `json:"reason,omitempty"`
	Selectors             store.PrivacyErasureSelectors                    `json:"selectors"`
	Counts                map[string]int                                   `json:"counts,omitempty"`
	RecoveryFences        []store.PrivacyRecoveryFenceDisposition          `json:"recovery_fences"`
	SchedulerDispositions []store.SecretRotationSchedulePrivacyDisposition `json:"scheduler_dispositions"`
}

type privacyIdentityTransitionV1 struct {
	IdentityID string `json:"identity_id"`
	From       string `json:"from"`
	To         string `json:"to"`
	Reason     string `json:"reason,omitempty"`
}

type privacyIdentityTransitionV2 struct {
	privacyIdentityTransitionV1
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type privacyIdentityTransitionV3 struct {
	privacyIdentityTransitionV2
	SubjectCSRPEM string                    `json:"subject_csr_pem,omitempty"`
	SideEffect    *identityTransitionEffect `json:"side_effect,omitempty"`
}

type privacyIdentityTransitionV4 struct {
	privacyIdentityTransitionV3
	Approval *store.OperationApprovalUse `json:"approval"`
}

type privacyIdentityTransitionV5 struct {
	privacyIdentityTransitionV3
	Issuance *store.OperationApprovalIssuanceBinding `json:"issuance"`
}

// Legacy CA hierarchy events were audit breadcrumbs with event-specific wire
// labels. They deliberately do not reuse CAAuthorityCreated: that v2 snapshot is
// a different schema even where a few coordinate names overlap.
type privacyLegacyCARootCreated struct {
	CAID       string `json:"ca_id"`
	CommonName string `json:"common_name"`
	CeremonyID string `json:"ceremony_id"`
}

type privacyLegacyCARootCreatedWithSigner struct {
	CAID         string `json:"ca_id"`
	CommonName   string `json:"common_name"`
	CeremonyID   string `json:"ceremony_id"`
	SignerHandle string `json:"signer_handle"`
}

type privacyLegacyOfflineCARootCreated struct {
	CAID       string `json:"ca_id"`
	CommonName string `json:"common_name"`
	CeremonyID string `json:"ceremony_id"`
	Offline    bool   `json:"offline_root"`
}

type privacyLegacyCAAuthorityImported struct {
	CAID         string `json:"ca_id"`
	CommonName   string `json:"common_name"`
	CeremonyID   string `json:"ceremony_id"`
	SignerHandle string `json:"signer_handle"`
	Kind         string `json:"kind"`
	ChainSHA256  string `json:"chain_sha256"`
}

type privacyLegacyCAIntermediateCreated struct {
	CAID       string `json:"ca_id"`
	ParentID   string `json:"parent_id"`
	CeremonyID string `json:"ceremony_id"`
}

type privacyLegacyCAIntermediateCreatedWithSigner struct {
	CAID         string `json:"ca_id"`
	ParentID     string `json:"parent_id"`
	CeremonyID   string `json:"ceremony_id"`
	SignerHandle string `json:"signer_handle"`
}

type privacyLegacyOfflineCAIntermediateCreated struct {
	CAID         string `json:"ca_id"`
	ParentID     string `json:"parent_id"`
	CeremonyID   string `json:"ceremony_id"`
	SignerHandle string `json:"signer_handle"`
	Offline      bool   `json:"offline_root"`
}

type privacyLegacyCRLPublishedV1 struct {
	CAID    string `json:"ca_id"`
	Number  int64  `json:"crl_number"`
	Revoked int    `json:"revoked"`
}

type privacyLegacyCRLPublishedV2 struct {
	CAID         string    `json:"ca_id"`
	Number       int64     `json:"crl_number"`
	DER          []byte    `json:"crl_der"`
	ThisUpdate   time.Time `json:"this_update"`
	NextUpdate   time.Time `json:"next_update"`
	RevokedCount int       `json:"revoked_count,omitempty"`
}

type privacyManagedKeyCommandV1 struct {
	OperationID    string `json:"operation_id"`
	Provider       string `json:"provider"`
	Action         string `json:"action"`
	KeyID          string `json:"key_id,omitempty"`
	Algorithm      string `json:"algorithm"`
	RequestBinding string `json:"request_binding"`
}

type privacyManagedKeyCommandV2 struct {
	OperationID          string                     `json:"operation_id"`
	Provider             string                     `json:"provider"`
	Action               string                     `json:"action"`
	KeyID                string                     `json:"key_id"`
	Algorithm            string                     `json:"algorithm"`
	RequestBinding       string                     `json:"request_binding"`
	Requester            string                     `json:"requester"`
	FromState            string                     `json:"from_state"`
	ToState              string                     `json:"to_state"`
	TargetVersion        uint64                     `json:"target_version"`
	IdempotencyKeyDigest string                     `json:"idempotency_key_digest"`
	ApprovalEvidenceRefs []string                   `json:"approval_evidence_refs"`
	Approval             store.OperationApprovalUse `json:"approval"`
}

type privacyManagedKeyCommandCompletedV1 struct {
	privacyManagedKeyCommandV1
	ResultKeyID string `json:"result_key_id"`
	PublicDER   []byte `json:"public_der"`
	State       string `json:"state"`
}

type privacyManagedKeyCommandCompletedV2 struct {
	privacyManagedKeyCommandV2
	ResultKeyID string `json:"result_key_id"`
	PublicDER   []byte `json:"public_der"`
	State       string `json:"state"`
}

type privacySecretSyncQueuedV1 struct {
	ID             string `json:"id"`
	SecretName     string `json:"secret_name"`
	SecretVersion  int64  `json:"secret_version"`
	Target         string `json:"target"`
	RemoteKey      string `json:"remote_key"`
	ValueDigest    string `json:"value_digest"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestBinding string `json:"request_binding,omitempty"`
	Sealed         []byte `json:"sealed"`
}

type privacySecretSyncQueuedV2 struct {
	TenantEpoch    string `json:"tenant_epoch"`
	ID             string `json:"id"`
	SecretName     string `json:"secret_name"`
	SecretVersion  int64  `json:"secret_version"`
	Target         string `json:"target"`
	RemoteKey      string `json:"remote_key"`
	ValueDigest    string `json:"value_digest"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestBinding string `json:"request_binding,omitempty"`
	Sealed         []byte `json:"sealed"`
}

type privacySecretSyncDeliveredV1 struct {
	ID            string `json:"id"`
	Attempts      int    `json:"attempts"`
	RemoteVersion string `json:"remote_version,omitempty"`
}

type privacySecretSyncDeliveredV2 struct {
	ID            string `json:"id"`
	TenantEpoch   string `json:"tenant_epoch"`
	Attempts      int    `json:"attempts"`
	RemoteVersion string `json:"remote_version,omitempty"`
}

type privacySecretSyncFailedV1 struct {
	ID       string `json:"id"`
	Attempts int    `json:"attempts"`
	Error    string `json:"error"`
}

type privacySecretSyncFailedV2 struct {
	ID          string `json:"id"`
	TenantEpoch string `json:"tenant_epoch"`
	Attempts    int    `json:"attempts"`
	Error       string `json:"error"`
}

func privacyPayloadShape[T any]() events.PrivacyPayloadShape {
	return events.PrivacyPayloadShapeOf[T]()
}

func exactProjectorPrivacyPayloadShapes() map[privacyEventPolicyKey]events.PrivacyPayloadShape {
	shapes := map[privacyEventPolicyKey]events.PrivacyPayloadShape{
		{EventOwnerCreated, 1}:                                                       privacyPayloadShape[OwnerCreated](),
		{EventOwnerUpdated, 1}:                                                       privacyPayloadShape[OwnerUpdated](),
		{EventOwnerDeleted, 1}:                                                       privacyPayloadShape[OwnerDeleted](),
		{EventApprovalRequested, 1}:                                                  privacyPayloadShape[ApprovalRequested](),
		{EventApprovalDecisionRecorded, 1}:                                           privacyPayloadShape[ApprovalDecisionRecorded](),
		{EventApprovalStatusChanged, 1}:                                              privacyPayloadShape[ApprovalStatusChanged](),
		{EventIssuanceRequestOpened, 1}:                                              privacyPayloadShape[IssuanceRequestOpened](),
		{EventIssuanceRequestDecided, 1}:                                             privacyPayloadShape[IssuanceRequestDecided](),
		{EventIdentityCreated, 1}:                                                    privacyPayloadShape[IdentityCreated](),
		{EventTenantMemberUpserted, 1}:                                               privacyPayloadShape[TenantMemberUpserted](),
		{EventTenantMemberOffboarded, 1}:                                             privacyPayloadShape[TenantMemberOffboarded](),
		{EventAPITokenCreated, 1}:                                                    privacyPayloadShape[APITokenCreated](),
		{EventAPITokenRevoked, 1}:                                                    privacyPayloadShape[APITokenRevoked](),
		{EventPAMSessionStarted, 1}:                                                  privacyPayloadShape[PAMSessionStarted](),
		{EventPAMSessionExpired, 1}:                                                  privacyPayloadShape[PAMSessionExpired](),
		{EventAgentHeartbeat, 1}:                                                     privacyPayloadShape[AgentHeartbeat](),
		{EventAgentCertRenewed, 1}:                                                   privacyPayloadShape[AgentCertRenewed](),
		{EventAgentCertRevoked, 1}:                                                   privacyPayloadShape[AgentCertRevoked](),
		{EventAgentOffboarded, 1}:                                                    privacyPayloadShape[AgentOffboarded](),
		{EventProfileCreated, 1}:                                                     privacyPayloadShape[privacyProfileV1](),
		{EventProfileUpdated, 1}:                                                     privacyPayloadShape[privacyProfileV1](),
		{EventProfileCreated, ProfileEventSchemaVersion}:                             privacyPayloadShape[ProfileVersioned](),
		{EventProfileUpdated, ProfileEventSchemaVersion}:                             privacyPayloadShape[ProfileVersioned](),
		{EventDiscoverySegmentUpserted, 1}:                                           privacyPayloadShape[DiscoverySegmentUpserted](),
		{EventDiscoverySourceUpserted, 1}:                                            privacyPayloadShape[DiscoverySourceUpserted](),
		{EventDiscoveryRunQueued, 1}:                                                 privacyPayloadShape[privacyDiscoveryRunQueued](),
		{EventRevocationProbeQueued, 1}:                                              privacyPayloadShape[revocationhealth.Intent](),
		{EventRevocationHealthObserved, 1}:                                           privacyPayloadShape[revocationhealth.Observed](),
		{EventMigrationRunRecorded, 1}:                                               privacyPayloadShape[MigrationRunRecorded](),
		{EventDiscoveryFindingRecorded, 1}:                                           privacyPayloadShape[DiscoveryFindingRecorded](),
		{EventDiscoveryFindingTriageChanged, 1}:                                      privacyPayloadShape[DiscoveryFindingTriageChanged](),
		{EventComplianceReportScheduleUpserted, 1}:                                   privacyPayloadShape[ComplianceReportScheduleUpserted](),
		{EventSecretRotationScheduleRan, 1}:                                          privacyPayloadShape[privacySecretRotationRunV1](),
		{EventSecretRotationScheduleRan, 2}:                                          privacyPayloadShape[privacySecretRotationRunV2](),
		{EventSecretRotationScheduleRan, 3}:                                          privacyPayloadShape[SecretRotationScheduleRan](),
		{EventNotificationRoutingPolicyUpserted, 1}:                                  privacyPayloadShape[NotificationRoutingPolicyUpserted](),
		{EventNotificationThresholdDelivered, 1}:                                     privacyPayloadShape[NotificationThresholdDelivered](),
		{EventIncidentExecutionRecorded, 1}:                                          privacyPayloadShape[IncidentExecutionRecorded](),
		{EventIncidentFleetReissuanceRecorded, 1}:                                    privacyPayloadShape[IncidentFleetReissuanceRecorded](),
		{EventRemediationPlaybookRunRecorded, 1}:                                     privacyPayloadShape[RemediationPlaybookRunRecorded](),
		{EventNHIAccessReviewCampaignStarted, 1}:                                     privacyPayloadShape[NHIAccessReviewCampaignStarted](),
		{EventNHIAccessReviewItemDecided, 1}:                                         privacyPayloadShape[NHIAccessReviewItemDecided](),
		{EventAccessChangeRequestCreated, 1}:                                         privacyPayloadShape[AccessChangeRequestCreated](),
		{EventAccessChangeRequestDecided, 1}:                                         privacyPayloadShape[AccessChangeRequestDecided](),
		{EventCertificateRevoked, 1}:                                                 privacyPayloadShape[CertificateRevoked](),
		{EventCertificateRecorded, 1}:                                                privacyPayloadShape[privacyCertificateRecordedV1](),
		{EventCertificateRecorded, CertificateApprovalEventSchemaVersion}:            privacyPayloadShape[CertificateRecorded](),
		{EventPrivacySubjectErased, 1}:                                               privacyPayloadShape[privacySubjectErasedV1](),
		{EventPrivacySubjectErased, PrivacySubjectErasedOperationEventSchemaVersion}: privacyPayloadShape[privacySubjectErasedV2](),
		{EventPrivacySubjectErased, PrivacySubjectErasedEventSchemaVersion}:          privacyPayloadShape[privacySubjectErasedV3](),
		{EventPrivacyRetentionEnforced, 1}:                                           privacyPayloadShape[PrivacyRetentionEnforced](),
		{EventPrivacyArchiveErasureAttested, 1}:                                      privacyPayloadShape[PrivacyArchiveErasureAttested](),
	}
	for _, eventType := range []string{
		EventIdentityIssued, EventIdentityDeployed, EventIdentityRevoked,
		EventIdentityRenewing, EventIdentityRenewed, EventIdentityRetired,
	} {
		shapes[privacyEventPolicyKey{EventType: eventType, Version: 1}] = privacyPayloadShape[privacyIdentityTransitionV1]()
		shapes[privacyEventPolicyKey{EventType: eventType, Version: LifecycleEventSchemaVersion}] = privacyPayloadShape[privacyIdentityTransitionV2]()
		shapes[privacyEventPolicyKey{EventType: eventType, Version: LifecycleSideEffectEventSchemaVersion}] = privacyPayloadShape[privacyIdentityTransitionV3]()
		shapes[privacyEventPolicyKey{EventType: eventType, Version: LifecycleApprovalEventSchemaVersion}] = privacyPayloadShape[privacyIdentityTransitionV4]()
	}
	shapes[privacyEventPolicyKey{EventType: EventIdentityIssued, Version: LifecycleIssuanceEventSchemaVersion}] = privacyPayloadShape[privacyIdentityTransitionV5]()
	return shapes
}

// projectorPrivacyPayloadShapes closes schemas whose current privacy posture is
// explicit refusal rather than a field rewrite. The concrete payload type still
// matters: required append/import mode must reject a new field under the same
// version even when the existing schema was designed to carry no personal data.
func projectorPrivacyPayloadShapes() map[privacyEventPolicyKey]events.PrivacyPayloadShape {
	return map[privacyEventPolicyKey]events.PrivacyPayloadShape{
		{audit.EventTypeArchived, audit.ArchivedEventSchemaVersion}: privacyPayloadShape[audit.ArchivedEvent](),
		{EventTenantRegistered, 1}:                                  privacyPayloadShape[tenantRegistered](),
		{EventTenantOffboarded, 1}:                                  privacyPayloadShape[tenantOffboarded](),
		{EventOwnershipReconciled, 1}:                               privacyPayloadShape[OwnershipReconciled](),
		{EventCMDBScheduleConfigured, 1}:                            privacyPayloadShape[CMDBScheduleConfigured](),
		{EventTicketIntakeConfigured, 1}:                            privacyPayloadShape[TicketIntakeConfigured](),
		{EventEnrollmentDiagnosticObserved, 1}:                      privacyPayloadShape[EnrollmentDiagnosticObserved](),
		{EventMDMDeviceCorrelated, 1}:                               privacyPayloadShape[MDMDeviceCorrelated](),
		{EventMDMPollConfigured, 1}:                                 privacyPayloadShape[MDMPollConfigured](),
		{EventEdgeSegmentPolicySet, 1}:                              privacyPayloadShape[EdgeSegmentPolicySet](),
		{EventEdgeDelegationIssued, 1}:                              privacyPayloadShape[EdgeDelegationIssued](),
		{EventEdgeDelegationRevoked, 1}:                             privacyPayloadShape[EdgeDelegationRevoked](),
		{EventEdgeIssuanceReconciled, 1}:                            privacyPayloadShape[EdgeIssuanceReconciled](),
		{EventADCSDatabaseIngested, 1}:                              privacyPayloadShape[ADCSDatabaseIngested](),
		{EventADCSInventoryObserved, 1}:                             privacyPayloadShape[adcsdiscovery.InventoryObserved](),
		{EventOwnershipConflictResolved, 1}:                         privacyPayloadShape[OwnershipConflictResolved](),
		{EventAgentUpgradeCampaignOpened, 1}:                        privacyPayloadShape[AgentUpgradeCampaignOpened](),
		{EventAgentUpgradeCampaignAdvanced, 1}:                      privacyPayloadShape[AgentUpgradeCampaignAdvanced](),
		{EventAgentUpgradeRingAssigned, 1}:                          privacyPayloadShape[AgentUpgradeRingAssigned](),
		{EventAgentUpgradeRingDispatched, 1}:                        privacyPayloadShape[AgentUpgradeRingDispatched](),
		{EventIssuerCreated, 1}:                                     privacyPayloadShape[IssuerCreated](),
		{EventCertificateSuperseded, 1}:                             privacyPayloadShape[CertificateSuperseded](),
		{EventCAIssuedCertificate, 1}:                               privacyPayloadShape[CAIssuedCertificate](),
		{EventCACertificateRevoked, 1}:                              privacyPayloadShape[CACertificateRevoked](),
		{EventCACeremonyStarted, 1}:                                 privacyPayloadShape[CACeremonyStarted](),
		{EventCACeremonyApproved, 1}:                                privacyPayloadShape[CACeremonyApproved](),
		{EventCARootCreated, 1}: events.PrivacyPayloadShapeOneOf(
			privacyPayloadShape[privacyLegacyCARootCreated](),
			privacyPayloadShape[privacyLegacyCARootCreatedWithSigner](),
			privacyPayloadShape[privacyLegacyOfflineCARootCreated](),
		),
		{EventCARootCreated, CAAuthorityCreatedEventSchemaVersion}:       privacyPayloadShape[CAAuthorityCreated](),
		{EventCAAuthorityImported, 1}:                                    privacyPayloadShape[privacyLegacyCAAuthorityImported](),
		{EventCAAuthorityImported, CAAuthorityCreatedEventSchemaVersion}: privacyPayloadShape[CAAuthorityCreated](),
		{EventCAIntermediateCreated, 1}: events.PrivacyPayloadShapeOneOf(
			privacyPayloadShape[privacyLegacyCAIntermediateCreated](),
			privacyPayloadShape[privacyLegacyCAIntermediateCreatedWithSigner](),
			privacyPayloadShape[privacyLegacyOfflineCAIntermediateCreated](),
		),
		{EventCAIntermediateCreated, CAAuthorityCreatedEventSchemaVersion}:      privacyPayloadShape[CAAuthorityCreated](),
		{EventCAEndEntityIssued, 1}:                                             privacyPayloadShape[CAIssuedCertificate](),
		{EventCAAuthorityRotated, 1}:                                            privacyPayloadShape[CAAuthorityRotated](),
		{EventCAAuthorityRekeyed, 1}:                                            privacyPayloadShape[CAAuthorityRekeyed](),
		{EventCACrossSigned, 1}:                                                 privacyPayloadShape[BreakglassCeremonyCompleted](),
		{EventBreakglassIssued, 1}:                                              privacyPayloadShape[BreakglassCeremonyCompleted](),
		{EventBreakglassCARotated, 1}:                                           privacyPayloadShape[BreakglassCeremonyCompleted](),
		{EventBreakglassCACrossSigned, 1}:                                       privacyPayloadShape[BreakglassCeremonyCompleted](),
		{EventCRLPublished, 1}:                                                  privacyPayloadShape[privacyLegacyCRLPublishedV1](),
		{EventCRLPublished, 2}:                                                  privacyPayloadShape[privacyLegacyCRLPublishedV2](),
		{EventCRLPublished, CRLPublishedEventSchemaVersion}:                     privacyPayloadShape[CRLPublished](),
		{EventOCSPResponderRotated, 1}:                                          privacyPayloadShape[OCSPResponderRotated](),
		{EventKubernetesControllerPostureReported, 1}:                           privacyPayloadShape[KubernetesControllerPostureReported](),
		{EventProfileCreated, 1}:                                                privacyPayloadShape[ProfileVersioned](),
		{EventProfileUpdated, 1}:                                                privacyPayloadShape[ProfileVersioned](),
		{EventDiscoveryScheduleUpserted, 1}:                                     privacyPayloadShape[DiscoveryScheduleUpserted](),
		{EventDiscoveryRunStarted, 1}:                                           privacyPayloadShape[DiscoveryRunStarted](),
		{EventDiscoveryRunCompleted, 1}:                                         privacyPayloadShape[DiscoveryRunCompleted](),
		{EventACMEDNS01ProviderConfigUpserted, 1}:                               privacyPayloadShape[ACMEDNS01ProviderConfigUpserted](),
		{EventACMEDNS01ProviderConfigDeleted, 1}:                                privacyPayloadShape[ACMEDNS01ProviderConfigDeleted](),
		{EventACMEDNS01Preflighted, 1}:                                          privacyPayloadShape[ACMEDNS01Preflighted](),
		{EventACMEDNS01RecordPresented, 1}:                                      privacyPayloadShape[ACMEDNS01RecordChanged](),
		{EventACMEDNS01RecordCleaned, 1}:                                        privacyPayloadShape[ACMEDNS01RecordChanged](),
		{EventACMEUpstreamAuthorizationObserved, 1}:                             privacyPayloadShape[ACMEUpstreamAuthorizationObserved](),
		{EventEndpointVerified, 1}:                                              privacyPayloadShape[EndpointVerificationObserved](),
		{EventMDMSCEPPolicyUpserted, 1}:                                         privacyPayloadShape[MDMSCEPPolicyUpserted](),
		{EventMDMSCEPPolicyDeleted, 1}:                                          privacyPayloadShape[MDMSCEPPolicyDeleted](),
		{EventMDMSCEPChallengeRotated, 1}:                                       privacyPayloadShape[MDMSCEPChallengeRotated](),
		{EventWorkloadAttesterTrustSourceUpserted, 1}:                           privacyPayloadShape[WorkloadAttesterTrustSourceUpserted](),
		{EventWorkloadAttesterTrustSourceRotated, 1}:                            privacyPayloadShape[WorkloadAttesterTrustSourceRotated](),
		{EventWorkloadAttesterTrustSourceRevoked, 1}:                            privacyPayloadShape[WorkloadAttesterTrustSourceRevoked](),
		{EventWorkloadAttesterTrustSourceDeleted, 1}:                            privacyPayloadShape[WorkloadAttesterTrustSourceDeleted](),
		{EventSecretRotationScheduleUpserted, 1}:                                privacyPayloadShape[SecretRotationScheduleUpserted](),
		{EventSecretRotationScheduleRan, 1}:                                     privacyPayloadShape[SecretRotationScheduleRan](),
		{EventNotificationRead, 1}:                                              privacyPayloadShape[NotificationRead](),
		{EventNotificationChannelUpserted, 1}:                                   privacyPayloadShape[NotificationChannelUpserted](),
		{EventNotificationChannelDeleted, 1}:                                    privacyPayloadShape[NotificationChannelDeleted](),
		{EventNotificationRoutingPolicyDeleted, 1}:                              privacyPayloadShape[NotificationRoutingPolicyDeleted](),
		{EventNotificationTestQueued, 1}:                                        privacyPayloadShape[NotificationTestQueued](),
		{EventNotificationDeliveryRecorded, 1}:                                  privacyPayloadShape[NotificationDeliveryRecorded](),
		{EventCBOMAssetObserved, 1}:                                             privacyPayloadShape[CBOMAssetObserved](),
		{EventDeploymentTargetUpserted, 1}:                                      privacyPayloadShape[DeploymentTargetUpserted](),
		{EventDeploymentTargetDeleted, 1}:                                       privacyPayloadShape[DeploymentTargetDeleted](),
		{EventIdentityConnectorTargetBound, 1}:                                  privacyPayloadShape[IdentityConnectorTargetBound](),
		{EventConnectorDeliveryRecorded, 1}:                                     privacyPayloadShape[ConnectorDeliveryRecorded](),
		{EventLifecycleRotationRecorded, 1}:                                     privacyPayloadShape[LifecycleRotationRecorded](),
		{EventOutboxReconciliationConflictRecorded, 1}:                          privacyPayloadShape[OutboxReconciliationConflictRecorded](),
		{EventResponseIntegrationDispatched, 1}:                                 privacyPayloadShape[ResponseIntegrationDispatched](),
		{EventMachineSessionStarted, 1}:                                         privacyPayloadShape[MachineSessionStarted](),
		{EventMachineSessionRevoked, 1}:                                         privacyPayloadShape[MachineSessionRevoked](),
		{EventMachineAuthMethodDisabled, 1}:                                     privacyPayloadShape[MachineAuthMethodOverride](),
		{EventMachineAuthMethodEnabled, 1}:                                      privacyPayloadShape[MachineAuthMethodOverride](),
		{EventPQCMigrationCampaignStarted, 1}:                                   privacyPayloadShape[PQCMigrationCampaignStarted](),
		{EventPQCMigrationCampaignUpdated, 1}:                                   privacyPayloadShape[PQCMigrationCampaignUpdated](),
		{EventPQCMigrationCampaignFindingDispositioned, 1}:                      privacyPayloadShape[PQCMigrationCampaignFindingDispositioned](),
		{EventPQCMigrationCampaignClosed, 1}:                                    privacyPayloadShape[PQCMigrationCampaignClosed](),
		{EventTenantKeyDomainMigrationStarted, 1}:                               privacyPayloadShape[TenantKeyDomainSnapshot](),
		{EventTenantKeyDomainMigrationProgressed, 1}:                            privacyPayloadShape[TenantKeyDomainSnapshot](),
		{EventTenantKeyDomainMigrationCompleted, 1}:                             privacyPayloadShape[TenantKeyDomainSnapshot](),
		{EventTenantKeyDomainMigrationFailed, 1}:                                privacyPayloadShape[TenantKeyDomainSnapshot](),
		{EventTenantKeyDomainSealRequested, 1}:                                  privacyPayloadShape[TenantKeyDomainSnapshot](),
		{EventTenantKeyDomainSealFailed, 1}:                                     privacyPayloadShape[TenantKeyDomainSnapshot](),
		{EventTenantKeyDomainSealed, 1}:                                         privacyPayloadShape[TenantKeyDomainSnapshot](),
		{EventTenantKeyDomainUnsealRequested, 1}:                                privacyPayloadShape[TenantKeyDomainSnapshot](),
		{EventTenantKeyDomainUnsealed, 1}:                                       privacyPayloadShape[TenantKeyDomainSnapshot](),
		{EventLicensedCryptoMigrationStarted, 1}:                                privacyPayloadShape[LicensedCryptoMigrationStarted](),
		{EventLicensedCryptoMigrationAssetCompleted, 1}:                         privacyPayloadShape[LicensedCryptoMigrationAssetCompleted](),
		{EventLicensedCryptoMigrationRollbackCompleted, 1}:                      privacyPayloadShape[LicensedCryptoMigrationRollbackCompleted](),
		{EventCodeSigningCompleted, 1}:                                          privacyPayloadShape[CodeSigningCompleted](),
		{EventCodeSigningFailed, 1}:                                             privacyPayloadShape[CodeSigningFailed](),
		{EventCodeSigningEphemeralDestroyed, 1}:                                 privacyPayloadShape[CodeSigningCommandReference](),
		{EventManagedKeyCommandRequested, 1}:                                    privacyPayloadShape[privacyManagedKeyCommandV1](),
		{EventManagedKeyCommandRequested, ManagedKeyApprovalEventSchemaVersion}: privacyPayloadShape[privacyManagedKeyCommandV2](),
		{EventManagedKeyCommandCompleted, 1}:                                    privacyPayloadShape[privacyManagedKeyCommandCompletedV1](),
		{EventManagedKeyCommandCompleted, ManagedKeyApprovalEventSchemaVersion}: privacyPayloadShape[privacyManagedKeyCommandCompletedV2](),
		{EventManagedKeyCommandFailed, 1}:                                       privacyPayloadShape[ManagedKeyCommandFailed](),
		{EventDynamicSecretLeasePending, 1}:                                     privacyPayloadShape[privacyDynamicSecretLeasePendingV1](),
		{EventDynamicSecretLeasePending, DynamicSecretEventSchemaVersion}:       privacyPayloadShape[privacyDynamicSecretLeasePendingV2](),
		{EventDynamicSecretLeasePrepared, 1}:                                    privacyPayloadShape[privacyDynamicSecretLeasePreparedV1](),
		{EventDynamicSecretLeasePrepared, DynamicSecretEventSchemaVersion}:      privacyPayloadShape[privacyDynamicSecretLeasePreparedV2](),
		{EventDynamicSecretLeaseIssued, 1}: events.PrivacyPayloadShapeOneOf(
			privacyPayloadShape[privacyDynamicSecretLegacyLeaseAudit](),
			privacyPayloadShape[privacyDynamicSecretLeaseIssuedV1](),
		),
		{EventDynamicSecretLeaseIssued, DynamicSecretEventSchemaVersion}:         privacyPayloadShape[privacyDynamicSecretLeaseIssuedV2](),
		{EventDynamicSecretLeaseIssuanceFailed, 1}:                               privacyPayloadShape[privacyDynamicSecretLeaseFailureV1](),
		{EventDynamicSecretLeaseIssuanceFailed, DynamicSecretEventSchemaVersion}: privacyPayloadShape[privacyDynamicSecretLeaseFailureV2](),
		{EventDynamicSecretLeaseRenewed, 1}: events.PrivacyPayloadShapeOneOf(
			privacyPayloadShape[privacyDynamicSecretLegacyLeaseAudit](),
			privacyPayloadShape[privacyDynamicSecretLeaseRenewedV1](),
		),
		{EventDynamicSecretLeaseRenewed, DynamicSecretEventSchemaVersion}:             privacyPayloadShape[privacyDynamicSecretLeaseRenewedV2](),
		{EventDynamicSecretLeaseRevocationRequested, 1}:                               privacyPayloadShape[privacyDynamicSecretLeaseRevocationRequestedV1](),
		{EventDynamicSecretLeaseRevocationRequested, DynamicSecretEventSchemaVersion}: privacyPayloadShape[privacyDynamicSecretLeaseRevocationRequestedV2](),
		{EventDynamicSecretLeaseRevocationCompleted, 1}:                               privacyPayloadShape[privacyDynamicSecretLeaseRevocationCompletedV1](),
		{EventDynamicSecretLeaseRevocationCompleted, DynamicSecretEventSchemaVersion}: privacyPayloadShape[privacyDynamicSecretLeaseRevocationCompletedV2](),
		{EventDynamicSecretLeaseRevocationFailed, 1}:                                  privacyPayloadShape[privacyDynamicSecretLeaseFailureV1](),
		{EventDynamicSecretLeaseRevocationFailed, DynamicSecretEventSchemaVersion}:    privacyPayloadShape[privacyDynamicSecretLeaseFailureV2](),
		{EventDynamicSecretOperationRequested, 1}:                                     privacyPayloadShape[privacyDynamicSecretOperationRequestedV1](),
		{EventDynamicSecretOperationRequested, DynamicSecretEventSchemaVersion}:       privacyPayloadShape[privacyDynamicSecretOperationRequestedV2](),
		{EventDynamicSecretOperationCompleted, 1}:                                     privacyPayloadShape[privacyDynamicSecretOperationCompletedV1](),
		{EventDynamicSecretOperationCompleted, DynamicSecretEventSchemaVersion}:       privacyPayloadShape[privacyDynamicSecretOperationCompletedV2](),
		{EventSecretSyncQueued, 1}:                                                    privacyPayloadShape[privacySecretSyncQueuedV1](),
		{EventSecretSyncQueued, SecretSyncEventSchemaVersion}:                         privacyPayloadShape[privacySecretSyncQueuedV2](),
		{EventSecretSyncDelivered, 1}:                                                 privacyPayloadShape[privacySecretSyncDeliveredV1](),
		{EventSecretSyncDelivered, SecretSyncEventSchemaVersion}:                      privacyPayloadShape[privacySecretSyncDeliveredV2](),
		{EventSecretSyncFailed, 1}:                                                    privacyPayloadShape[privacySecretSyncFailedV1](),
		{EventSecretSyncFailed, SecretSyncEventSchemaVersion}:                         privacyPayloadShape[privacySecretSyncFailedV2](),
		{EventSecretSyncWorkloadIdentityUpserted, 1}:                                  privacyPayloadShape[SecretSyncWorkloadIdentitySourceUpserted](),
		{EventSecretSyncWorkloadIdentityStatus, 1}:                                    privacyPayloadShape[SecretSyncWorkloadIdentitySourceStatus](),
		{EventSecretSyncWorkloadIdentityDeleted, 1}:                                   privacyPayloadShape[SecretSyncWorkloadIdentitySourceDeleted](),
	}
}

// projectorRejectPrivacyRules closes the deliberately dynamic fields inside a
// typed reject policy. RejectSubjectData still makes erasure stop if the raw
// subject appears anywhere in these schemas; these rules only tell the
// subject-independent append/import validator that the named subtree is an
// intentional protocol blob rather than an undeclared same-version field.
func projectorRejectPrivacyRules() map[string][]events.PrivacyFieldRule {
	const (
		jsonID = events.PrivacyFieldJSONIdentityValues
		opaque = events.PrivacyFieldOpaqueExact
	)
	return map[string][]events.PrivacyFieldRule{
		EventACMEDNS01ProviderConfigUpserted: {
			privacyRule("/credential_refs", opaque),
			privacyRule("/config", jsonID),
		},
		EventMDMSCEPPolicyUpserted: {
			privacyRule("/trust_anchor_refs", opaque),
			privacyRule("/profile_guidance", opaque),
		},
		EventWorkloadAttesterTrustSourceUpserted: {
			privacyRule("/jwks", opaque),
		},
		EventWorkloadAttesterTrustSourceRotated: {
			privacyRule("/jwks", opaque),
		},
		EventNotificationTestQueued: {
			privacyRule("/payload", opaque),
		},
		EventDeploymentTargetUpserted: {
			privacyRule("/config", jsonID),
		},
		EventPQCMigrationCampaignClosed: {
			privacyRule("/public_jwks", opaque),
		},
		EventLicensedCryptoMigrationStarted: {
			privacyRule("/tls_postures/*/target_config", opaque),
			privacyRule("/tls_postures/*/sealed_outbox_payload", opaque),
		},
		EventCodeSigningCompleted: {
			privacyRule("/response", opaque),
			privacyRule("/rekor_payload", opaque),
		},
		EventDynamicSecretOperationRequested: {
			privacyRule("/response", opaque),
		},
	}
}

func init() {
	exact := exactProjectorPrivacyPolicies()
	exactShapes := exactProjectorPrivacyPayloadShapes()
	shapes := projectorPrivacyPayloadShapes()
	rejectRules := projectorRejectPrivacyRules()
	for eventType, versions := range knownSchemaVersions {
		for version := range versions {
			if events.HasPrivacyEventPolicy(eventType, version) {
				continue
			}
			policy, ok := exact[privacyEventPolicyKey{EventType: eventType, Version: version}]
			if ok {
				shape, found := exactShapes[privacyEventPolicyKey{EventType: eventType, Version: version}]
				if !found {
					panic(fmt.Sprintf("no concrete exact privacy payload shape for projector event %s v%d", eventType, version))
				}
				policy.PayloadShape = shape
			} else {
				shape, found := shapes[privacyEventPolicyKey{EventType: eventType, Version: version}]
				if !found {
					panic(fmt.Sprintf("no closed privacy payload shape for projector event %s v%d", eventType, version))
				}
				policy = events.PrivacyEventPolicy{
					Rules:             append([]events.PrivacyFieldRule(nil), rejectRules[eventType]...),
					PayloadShape:      shape,
					RejectSubjectData: true,
				}
			}
			if err := events.RegisterPrivacyEventPolicy(eventType, version, policy); err != nil {
				panic(fmt.Sprintf("register exact privacy policy for %s v%d: %v", eventType, version, err))
			}
		}
	}
}
