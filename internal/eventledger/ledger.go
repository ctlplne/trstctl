// Package eventledger is the single source of truth that binds every mutating
// served GA capability to the immutable AN-2 event it emits (COVER-008). The audit
// finding was that some mutating GA paths had no defined event, so an auditor could
// not filter the who-did-what-when trail by the feature or action that produced it.
//
// It is a leaf package with no trstctl-internal imports on purpose: the audit query
// layer (internal/audit) is downstream of internal/store, which imports internal/audit
// for its checkpoint types, so internal/audit cannot import internal/projections
// (that would be an import cycle). A standalone ledger that both internal/audit and
// internal/projections can read keeps the catalog in one place. internal/projections
// re-exports it and a projections test cross-checks every event string here against
// the projector's event-type constants, so the two can never drift.
//
// The ledger closes the gap two ways, both enforced by tests:
//
//   - completeness: every entry names a non-empty event type, and every event the
//     orchestrator/lifecycle actually emits maps back to a ledger entry (no served
//     mutation can quietly emit an event that is not catalogued, and no catalogued
//     action can point at an empty event);
//   - filterability: the audit query layer resolves a feature_id/action filter to
//     the event types in this ledger, so an operator can ask "show me every
//     revocation" without memorising raw event-type strings.
//
// Feature ids match the catalog in docs/features.tsv; actions are the stable verb an
// operator reasons about. The ledger is keyed by (feature_id, action) so the same
// action under different features stays distinct, and one logical action can emit
// several event types (e.g. a profile version emits profile.created or
// profile.updated; a renewal emits identity.renewing then identity.renewed).
package eventledger

import "sort"

// Event type names. These mirror internal/projections' Event* constants; a
// projections test asserts they stay equal so the catalog cannot drift from the
// shapes the projector actually decodes.
const (
	EventCertificateRecorded              = "certificate.recorded"
	EventCertificateRevoked               = "certificate.revoked"
	EventCertificateSuperseded            = "certificate.superseded"
	EventCACeremonyStarted                = "ca.ceremony.started"
	EventCACeremonyApproved               = "ca.ceremony.approved"
	EventCARootCreated                    = "ca.root.created"
	EventCAAuthorityImported              = "ca.authority.imported"
	EventCAAuthorityRotated               = "ca.authority.rotated"
	EventCAAuthorityRekeyed               = "ca.authority.rekeyed"
	EventCAIntermediateCreated            = "ca.intermediate.created"
	EventCAIntermediateCSRIssued          = "ca.intermediate_csr.issued"
	EventCAEndEntityIssued                = "ca.endentity.issued"
	EventOCSPResponderRotated             = "ca.ocsp_responder.rotated"
	EventDiscoverySourceUpserted          = "discovery.source.upserted"
	EventDiscoveryScheduleUpserted        = "discovery.schedule.upserted"
	EventDiscoveryRunQueued               = "discovery.run.queued"
	EventDiscoveryFindingTriageChanged    = "discovery.finding.triage_changed"
	EventACMEDNS01ProviderConfigUpserted  = "acme.dns01.provider_config.upserted"
	EventACMEDNS01ProviderConfigDeleted   = "acme.dns01.provider_config.deleted"
	EventACMEDNS01Preflighted             = "acme.dns01.preflighted"
	EventMDMSCEPPolicyUpserted            = "mdm.scep_policy.upserted"
	EventMDMSCEPPolicyDeleted             = "mdm.scep_policy.deleted"
	EventMDMSCEPChallengeRotated          = "mdm.scep_challenge.rotated"
	EventComplianceReportScheduleUpserted = "compliance.report_schedule.upserted"
	EventCBOMAssetObserved                = "cbom.asset.observed"
	EventPQCMigrationStarted              = "pqc.migration.started"
	EventPQCMigrationAssetCompleted       = "pqc.migration.asset_completed"
	EventPQCMigrationRollbackCompleted    = "pqc.migration.rollback_completed"
	EventIdentityCreated                  = "identity.created"
	EventIdentityIssued                   = "identity.issued"
	EventIdentityDeployed                 = "identity.deployed"
	EventIdentityRenewing                 = "identity.renewing"
	EventIdentityRenewed                  = "identity.renewed"
	EventIdentityRevoked                  = "identity.revoked"
	EventIdentityRetired                  = "identity.retired"
	EventIssuerCreated                    = "issuer.created"
	EventDeploymentTargetUpserted         = "deployment_target.upserted"
	EventDeploymentTargetDeleted          = "deployment_target.deleted"
	EventIdentityConnectorTargetBound     = "identity.connector_target_bound"
	EventConnectorDeliveryRecorded        = "connector.delivery.recorded"
	EventLifecycleRotationRecorded        = "lifecycle.rotation.recorded"
	EventIncidentExecutionRecorded        = "incident.execution.recorded"
	EventIncidentFleetReissuanceRecorded  = "incident.fleet_reissuance.recorded"
	EventRemediationPlaybookRunRecorded   = "remediation.playbook_run.recorded"
	EventResponseIntegrationDispatched    = "response.integration.dispatched"
	EventOwnerCreated                     = "owner.created"
	EventOwnerUpdated                     = "owner.updated"
	EventOwnerDeleted                     = "owner.deleted"
	EventTenantMemberUpserted             = "tenant.member.upserted"
	EventTenantMemberOffboarded           = "tenant.member.offboarded"
	EventAPITokenCreated                  = "api_token.created"
	EventAPITokenRevoked                  = "api_token.revoked"
	EventPAMSessionStarted                = "pam.session.started"
	EventPAMSessionExpired                = "pam.session.expired"
	EventProfileCreated                   = "profile.created"
	EventProfileUpdated                   = "profile.updated"
	EventPrivacySubjectErased             = "privacy.subject.erased"
	EventPrivacyRetentionEnforced         = "privacy.retention.enforced"
	EventNHIAccessReviewCampaignStarted   = "nhi.access_review.campaign.started"
	EventNHIAccessReviewItemDecided       = "nhi.access_review.item.decided"
	EventAccessChangeRequestCreated       = "access.change_request.created"
	EventAccessChangeRequestDecided       = "access.change_request.decided"
)

// FeatureEvent is one row of the event-name ledger: the immutable AN-2 event types
// a single served mutating action emits. EventTypes holds one or more types when an
// action's event name depends on state (first-vs-later version, create-vs-update,
// the two phases of a renewal).
type FeatureEvent struct {
	FeatureID  string   // catalog feature id, e.g. "F9"
	Feature    string   // human title, for audit UI labels
	Action     string   // stable operator verb, e.g. "revoke"
	OpID       string   // the served OpenAPI operationId that drives this action
	EventTypes []string // the immutable event type(s) the action emits (AN-2)
}

// ledger is the authoritative feature/action -> event-name mapping for every
// mutating served GA path. Adding a served mutation without adding its row here
// (or the orchestrator emitting an event type absent from here) fails the
// projections completeness test.
var ledger = []FeatureEvent{
	// F1 — Certificate inventory.
	{"F1", "Certificate inventory", "ingest", "ingestCertificate", []string{EventCertificateRecorded}},
	// F47 — X.509 revocation infrastructure (served revocation of an inventoried cert).
	{"F47", "X.509 revocation infrastructure", "revoke", "transitionIdentity", []string{EventCertificateRevoked}},
	{"F47", "X.509 revocation infrastructure", "supersede", "transitionIdentity", []string{EventCertificateSuperseded}},
	{"F47", "X.509 revocation infrastructure", "rotate_ocsp_responder", "respondOCSP", []string{EventOCSPResponderRotated}},

	// F2 — Discovery (sources, schedules, runs).
	{"F2", "Network discovery", "create_source", "createDiscoverySource", []string{EventDiscoverySourceUpserted}},
	{"F2", "Network discovery", "create_schedule", "createDiscoverySchedule", []string{EventDiscoveryScheduleUpserted}},
	{"F2", "Network discovery", "start_run", "startDiscoveryRun", []string{EventDiscoveryRunQueued}},
	{"F2", "Network discovery", "triage_finding", "claimDiscoveryFinding", []string{EventDiscoveryFindingTriageChanged}},
	{"F2", "Network discovery", "dismiss_finding", "dismissDiscoveryFinding", []string{EventDiscoveryFindingTriageChanged}},
	{"F52", "Cryptographic Bill of Materials", "scan", "startCBOMScan", []string{EventCBOMAssetObserved}},
	{"F57", "PQC migration orchestration", "start", "startPQCMigration", []string{EventPQCMigrationStarted, EventPQCMigrationAssetCompleted}},
	{"F57", "PQC migration orchestration", "rollback", "rollbackPQCMigration", []string{EventPQCMigrationRollbackCompleted}},

	// F69-F74 — served ACME DNS-01 provider configuration and validation policy.
	{"F69", "DNS-01 challenge automation", "configure_provider", "createACMEDNS01ProviderConfig", []string{EventACMEDNS01ProviderConfigUpserted}},
	{"F69", "DNS-01 challenge automation", "delete_provider", "deleteACMEDNS01ProviderConfig", []string{EventACMEDNS01ProviderConfigDeleted}},
	{"F69", "DNS-01 challenge automation", "preflight", "preflightACMEDNS01", []string{EventACMEDNS01Preflighted}},
	{"F70", "DNS-provider plugin framework", "configure_provider", "createACMEDNS01ProviderConfig", []string{EventACMEDNS01ProviderConfigUpserted}},
	{"F70", "DNS-provider plugin framework", "delete_provider", "deleteACMEDNS01ProviderConfig", []string{EventACMEDNS01ProviderConfigDeleted}},
	{"F71", "CNAME delegation for validation isolation", "preflight_delegation", "preflightACMEDNS01", []string{EventACMEDNS01Preflighted}},
	{"F72", "CAA policy enforcement and management", "preflight_caa", "preflightACMEDNS01", []string{EventACMEDNS01Preflighted}},
	{"F73", "Multi-method domain-validation policy", "preflight_method", "preflightACMEDNS01", []string{EventACMEDNS01Preflighted}},
	{"F74", "Automated wildcard issuance and renewal", "preflight_wildcard", "preflightACMEDNS01", []string{EventACMEDNS01Preflighted}},

	// F56 — served MDM/SCEP challenge policy management for Intune/JAMF profiles.
	{"F56", "Intune / MDM enrollment integration", "create_policy", "createMDMSCEPPolicy", []string{EventMDMSCEPPolicyUpserted}},
	{"F56", "Intune / MDM enrollment integration", "delete_policy", "deleteMDMSCEPPolicy", []string{EventMDMSCEPPolicyDeleted}},
	{"F56", "Intune / MDM enrollment integration", "rotate_challenge", "rotateMDMSCEPChallenge", []string{EventMDMSCEPChallengeRotated}},

	// F4/F6 — CA-agnostic issuance and lifecycle automation, driven by the lifecycle
	// state machine (internal/orchestrator/lifecycle.go). Each transition emits one
	// identity.* event; the ledger lists them under their owning feature.
	{"F4", "CA-agnostic outbound issuance", "issue", "transitionIdentity", []string{EventIdentityIssued}},
	{"F6", "Lifecycle automation", "create_identity", "createIdentity", []string{EventIdentityCreated}},
	{"F6", "Lifecycle automation", "deploy", "transitionIdentity", []string{EventIdentityDeployed}},
	{"F6", "Lifecycle automation", "renew", "transitionIdentity", []string{EventIdentityRenewing, EventIdentityRenewed}},
	{"F6", "Lifecycle automation", "revoke", "transitionIdentity", []string{EventIdentityRevoked}},
	{"F6", "Lifecycle automation", "retire", "transitionIdentity", []string{EventIdentityRetired}},
	{"F6", "Lifecycle automation", "rotation_recorded", "executeIncident", []string{EventLifecycleRotationRecorded}},

	// F48 — Private/enterprise CA hierarchy (issuer registration + served hierarchy).
	{"F48", "Private/enterprise CA hierarchy management", "create_issuer", "createIssuer", []string{EventIssuerCreated}},
	{"F48", "Private/enterprise CA hierarchy management", "start_ceremony", "createCACeremony", []string{EventCACeremonyStarted}},
	{"F48", "Private/enterprise CA hierarchy management", "approve_ceremony", "approveCACeremony", []string{EventCACeremonyApproved}},
	{"F48", "Private/enterprise CA hierarchy management", "create_root", "createRootCA", []string{EventCARootCreated}},
	{"F48", "Private/enterprise CA hierarchy management", "import_offline_root", "importOfflineRootCA", []string{EventCARootCreated}},
	{"F48", "Private/enterprise CA hierarchy management", "import_existing_ca", "importExistingCA", []string{EventCAAuthorityImported}},
	{"F48", "Private/enterprise CA hierarchy management", "create_intermediate", "createIntermediateCA", []string{EventCAIntermediateCreated}},
	{"F48", "Private/enterprise CA hierarchy management", "create_offline_intermediate_csr", "createOfflineIntermediateCSR", []string{EventCAIntermediateCSRIssued}},
	{"F48", "Private/enterprise CA hierarchy management", "import_offline_intermediate", "importOfflineIntermediateCA", []string{EventCAIntermediateCreated}},
	{"F48", "Private/enterprise CA hierarchy management", "issue_external_intermediate", "issueIntermediateCAFromCSR", []string{EventCAIntermediateCSRIssued}},
	{"F48", "Private/enterprise CA hierarchy management", "issue_leaf", "issueHierarchyLeaf", []string{EventCAEndEntityIssued}},
	{"F48", "Private/enterprise CA hierarchy management", "rotate_authority", "rotateCAAuthority", []string{EventCAAuthorityRotated}},
	{"F48", "Private/enterprise CA hierarchy management", "rekey_authority", "rekeyCAAuthority", []string{EventCAAuthorityRekeyed}},

	// F7 — Deployment connectors (delivery receipts are event-sourced evidence).
	{"F7", "Deployment connectors", "upsert_target", "createConnectorTarget", []string{EventDeploymentTargetUpserted}},
	{"F7", "Deployment connectors", "delete_target", "deleteConnectorTarget", []string{EventDeploymentTargetDeleted}},
	{"F7", "Deployment connectors", "bind_target", "bindIdentityConnectorTarget", []string{EventIdentityConnectorTargetBound}},
	{"F7", "Deployment connectors", "record_delivery", "executeIncident", []string{EventConnectorDeliveryRecorded}},

	// F47 — Incident remediation evidence pack.
	{"F47", "Incident remediation", "execute_incident", "executeIncident", []string{EventIncidentExecutionRecorded}},
	{"F47", "Incident remediation", "run_playbook", "runRemediationPlaybook", []string{EventRemediationPlaybookRunRecorded}},
	{"F47", "Incident remediation", "dispatch_response_integrations", "dispatchResponseIntegrations", []string{EventResponseIntegrationDispatched}},
	{"F32", "CA compromise fleet reissuance", "start_fleet_reissuance", "startFleetReissuance", []string{EventIncidentFleetReissuanceRecorded}},
	{"F32", "CA compromise fleet reissuance", "pause_fleet_reissuance", "pauseFleetReissuance", []string{EventIncidentFleetReissuanceRecorded}},
	{"F32", "CA compromise fleet reissuance", "resume_fleet_reissuance", "resumeFleetReissuance", []string{EventIncidentFleetReissuanceRecorded}},
	{"F32", "CA compromise fleet reissuance", "rollback_fleet_reissuance", "rollbackFleetReissuance", []string{EventIncidentFleetReissuanceRecorded}},

	// F8 — RBAC: owners, tenant members, API tokens.
	{"F8", "RBAC", "create_owner", "createOwner", []string{EventOwnerCreated}},
	{"F8", "RBAC", "update_owner", "updateOwner", []string{EventOwnerUpdated}},
	{"F8", "RBAC", "delete_owner", "deleteOwner", []string{EventOwnerDeleted}},
	{"F8", "RBAC", "upsert_member", "upsertMember", []string{EventTenantMemberUpserted}},
	{"F8", "RBAC", "offboard_member", "offboardMember", []string{EventTenantMemberOffboarded}},
	{"F8", "RBAC", "create_api_token", "createAPIToken", []string{EventAPITokenCreated}},
	{"F8", "RBAC", "revoke_api_token", "revokeAPIToken", []string{EventAPITokenRevoked}},

	// F33 — Just-in-time privileged access sessions.
	{"F33", "Just-in-time issuance with approval flows", "open_pam_session", "openPAMSession", []string{EventPAMSessionStarted}},
	{"F33", "Just-in-time issuance with approval flows", "expire_pam_session", "openPAMSession", []string{EventPAMSessionExpired}},

	// F28 — policy/governance access-change approval workflow with PR evidence.
	{"F28", "Policy engine", "create_access_change_request", "createAccessChangeRequest", []string{EventAccessChangeRequestCreated}},
	{"F28", "Policy engine", "decide_access_change_request", "decideAccessChangeRequest", []string{EventAccessChangeRequestDecided}},

	// F4 — Certificate profiles (a version emits created on v1, updated after).
	{"F4", "Certificate profiles", "create_profile", "createProfile", []string{EventProfileCreated, EventProfileUpdated}},

	// F9 — Privacy operations (subject erasure, retention enforcement).
	{"F9", "Privacy subject erasure", "erase_subject", "erasePrivacySubject", []string{EventPrivacySubjectErased}},
	{"F9", "Privacy retention", "enforce_retention", "enforcePrivacyRetention", []string{EventPrivacyRetentionEnforced}},

	// F62 — IGA-grade NHI access-review / certification campaigns.
	{"F62", "Cryptographic compliance reporting & posture dashboards", "schedule_report", "createComplianceReportSchedule", []string{EventComplianceReportScheduleUpserted}},
	{"F62", "NHI access certification campaigns", "start_nhi_review", "startNHIReviewCampaign", []string{EventNHIAccessReviewCampaignStarted}},
	{"F62", "NHI access certification campaigns", "decide_nhi_review_item", "decideNHIReviewItem", []string{EventNHIAccessReviewItemDecided}},
}

// eventTypeSet is the flattened set of every event type catalogued above, built
// once. It is the denominator the completeness test uses to prove no emitted event
// escapes the ledger.
var eventTypeSet = func() map[string]struct{} {
	s := make(map[string]struct{})
	for _, fe := range ledger {
		for _, t := range fe.EventTypes {
			s[t] = struct{}{}
		}
	}
	return s
}()

// Ledger returns a copy of the feature/action -> event-name ledger. Callers (the
// audit query layer, conformance tests) read it; they do not mutate it.
func Ledger() []FeatureEvent {
	out := make([]FeatureEvent, len(ledger))
	copy(out, ledger)
	return out
}

// EventTypesForFeatureAction resolves a (feature_id, action) selector to the event
// types it emits, for audit filtering. featureID and action are matched
// case-sensitively; either may be empty to widen the match:
//
//   - both empty: returns (nil, false) so the caller skips the filter entirely;
//   - featureID only: every event type any action of that feature emits;
//   - action only: every event type that action emits across features;
//   - both set: that action's event types.
//
// ok reports whether the selector named anything to filter on. A selector that
// matches no ledger row returns (nil, true): the audit query then yields zero
// records, which is the correct answer for "filter by a feature/action that has no
// events" rather than silently returning the unfiltered log.
func EventTypesForFeatureAction(featureID, action string) (types []string, ok bool) {
	if featureID == "" && action == "" {
		return nil, false
	}
	seen := map[string]struct{}{}
	for _, fe := range ledger {
		if featureID != "" && fe.FeatureID != featureID {
			continue
		}
		if action != "" && fe.Action != action {
			continue
		}
		for _, t := range fe.EventTypes {
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			types = append(types, t)
		}
	}
	sort.Strings(types)
	return types, true
}

// HasEventType reports whether t is catalogued in the ledger. The completeness test
// uses it to assert every emitted lifecycle/orchestrator event type maps back to a
// ledger entry.
func HasEventType(t string) bool {
	_, ok := eventTypeSet[t]
	return ok
}

// EventTypes returns every distinct event type the ledger catalogues, sorted.
func EventTypes() []string {
	out := make([]string, 0, len(eventTypeSet))
	for t := range eventTypeSet {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
