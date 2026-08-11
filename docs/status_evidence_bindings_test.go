// SPDX-License-Identifier: MPL-2.0

package docs

// EvidenceBinding ties one verdict-shaped field in the generated API to the
// minimum evidence that licenses the value and to the production component
// that writes or derives it. The generated-contract guard in docs walks every
// served status/outcome field and requires an exact entry here, so adding a new
// operator-readable verdict cannot silently escape the truth-integrity review.
type EvidenceBinding struct {
	Schema    string
	Field     string
	Predicate EvidencePredicate
	Writer    string
}

// EvidenceClass is deliberately closed. A free-form sentence can explain a
// predicate, but it cannot substitute for deciding what kind of production
// fact licenses a verdict.
type EvidenceClass string

const (
	evidenceEventProjection EvidenceClass = "event_projection"
	evidenceWorkflow        EvidenceClass = "workflow"
	evidenceObservation     EvidenceClass = "observation"
	evidenceConfiguration   EvidenceClass = "configuration"
	evidenceProtocol        EvidenceClass = "protocol"
	evidenceAttestation     EvidenceClass = "attestation"
)

type EvidencePredicate struct {
	Class       EvidenceClass
	Requirement string
}

var (
	eventProjectionPredicate   = predicate(evidenceEventProjection, "an immutable tenant event was appended and this value was rebuilt by its named projection")
	operationApprovalPredicate = predicate(evidenceEventProjection, "the value is copied from the tenant-scoped operation-approval read model rebuilt from immutable approval request, decision, status-change, and consumption events; no inventory row or reviewer input can manufacture it")
	workflowPredicate          = predicate(evidenceWorkflow, "the named production workflow recorded this exact lifecycle value; the value does not imply external verification unless its surface registry says so")
	observationPredicate       = predicate(evidenceObservation, "the named production observer derived this value from a target response or durable observation, with absence represented separately")
	configurationPredicate     = predicate(evidenceConfiguration, "the named production configuration evaluator derived this value without claiming that it contacted or changed an external target")
	protocolPredicate          = predicate(evidenceProtocol, "the named protocol handler recorded this value from the accepted or rejected protocol exchange")
	attestationPredicate       = predicate(evidenceAttestation, "the named evidence writer recorded this value with actor/source attribution; it is an attestation unless a stronger surface-specific predicate says otherwise")
)

func predicate(class EvidenceClass, requirement string) EvidencePredicate {
	return EvidencePredicate{Class: class, Requirement: requirement}
}

func evidence(schema, field string, predicate EvidencePredicate, writer string) EvidenceBinding {
	return EvidenceBinding{Schema: schema, Field: field, Predicate: predicate, Writer: writer}
}

// servedEvidenceBindings is intentionally explicit. Replacing these entries with a
// wildcard or a default would recreate AUD-57: a new status-bearing DTO would
// look covered while nobody had decided what evidence its words require.
var servedEvidenceBindings = []EvidenceBinding{
	evidence("ACMEDNS01PreflightCheck", "status", observationPredicate, "internal/api/acme_dns01.go:API.evaluateDNS01Preflight"),
	evidence("AccessChangeRequest", "status", eventProjectionPredicate, "internal/orchestrator/access_change_request.go:Orchestrator.CreateAccessChangeRequest"),
	evidence("Agent", "status", observationPredicate, "internal/api/agents.go:toAgentResponse"),
	evidence("AgentUpgradeCampaign", "status", eventProjectionPredicate, "internal/orchestrator/agent_upgrade.go:Orchestrator.OpenAgentUpgradeCampaign"),
	evidence("Approval", "status", operationApprovalPredicate, "internal/api/approvals.go:approvalResponseFor"),
	evidence("ApprovalDecision", "status", operationApprovalPredicate, "internal/api/approvals.go:approvalResponseFor"),
	evidence("BreakglassCeremony", "status", eventProjectionPredicate, "internal/api/breakglass.go:API.startBreakglassIssueCeremony"),
	evidence("BulkRevokeItem", "status", workflowPredicate, "internal/api/bulk_revoke.go:API.bulkRevoke"),
	evidence("BulkRevokeRequest", "status", workflowPredicate, "internal/api/bulk_revoke.go:API.bulkRevoke"),
	evidence("CAAuthority", "status", eventProjectionPredicate, "internal/api/ca_hierarchy.go:API.listCAAuthorities"),
	evidence("CAAuthorityRotationIssuer", "status", eventProjectionPredicate, "internal/api/ca_hierarchy.go:API.rotateCAAuthority"),
	evidence("CADiscoveryItem", "status", observationPredicate, "internal/api/ca_discovery.go:API.listCADiscoveryInventory"),
	evidence("CAKeyCeremony", "status", eventProjectionPredicate, "internal/api/ca_hierarchy.go:API.createCACeremony"),
	evidence("Certificate", "status", eventProjectionPredicate, "internal/projections/projections.go:Projector.Apply"),
	evidence("CertificateHealthItem", "status", observationPredicate, "internal/api/certificates.go:toCertificateHealthDashboard"),
	evidence("CodeSigningIdentity", "status", eventProjectionPredicate, "internal/api/codesign_identities.go:API.listCodeSigningIdentities"),
	evidence("ConnectorDelivery", "status", predicate(evidenceObservation, "the connector receipt registry binds each value to queued, contacted, mutated, or independently verified evidence"), "internal/orchestrator/commands.go:Orchestrator.RecordConnectorDelivery"),
	evidence("DRDrill", "outcome", predicate(evidenceObservation, "restored requires the delivered full backup set to restore into isolated ephemeral data and messaging targets; failed and skipped record why that predicate was not met"), "internal/server/drill.go:RunRestoreDrill"),
	evidence("DiscoveryCoverageClass", "status", observationPredicate, "internal/api/discovery.go:API.getDiscoveryCoverage"),
	evidence("DiscoveryRun", "status", eventProjectionPredicate, "internal/orchestrator/discovery.go:Orchestrator.CompleteDiscoveryRun"),
	evidence("DiscoverySegmentCoverage", "status", observationPredicate, "internal/api/discovery.go:API.getDiscoveryCoverage"),
	evidence("EdgeDelegation", "status", eventProjectionPredicate, "internal/api/edge_delegation.go:API.listEdgeDelegations"),
	evidence("EndpointVerification", "status", predicate(evidenceObservation, "verified/diverged require a live listener handshake receipt; unreachable/not_checked explicitly carry no positive verdict"), "internal/api/endpoint_verification.go:endpointVerificationStatus"),
	evidence("EphemeralApproval", "status", operationApprovalPredicate, "internal/server/ephemeral.go:ephemeralIssuerService.ApproveEphemeralCredential"),
	evidence("ExternalCA", "status", observationPredicate, "internal/api/external_ca.go:API.listExternalCAs"),
	evidence("FIPSCustodyValidationCertificate", "status", attestationPredicate, "internal/compliance/fips.go:FIPSCustodyValidationCertificates"),
	evidence("FleetReissuanceBatch", "health_gate", predicate(evidenceObservation, "the verdict is computed only from this batch's endpoint-verification receipts whose matching agent signature was accepted; missing or unsigned evidence remains not_evaluated"), "internal/store/connector_lifecycle.go:Store.SummarizeFleetVerification"),
	evidence("FleetReissuanceBatch", "status", predicate(evidenceWorkflow, "executed/failed require that batch to run as a mutation unit; halted means it was never published after an earlier signed verification failure"), "internal/server/fleet_reissuance_worker.go:issuanceDispatcher.handleFleetReissuanceBatch"),
	evidence("FleetReissuanceHealthGate", "status", predicate(evidenceObservation, "passed/failed require a named evidence evaluation; no receipt set remains not_evaluated"), "internal/api/incident_fleet_reissuance.go:evaluateFleetDeploymentGate"),
	evidence("FleetReissuanceRun", "status", predicate(evidenceEventProjection, "the value is the persisted event-sourced run phase and durable cursor; completion requires every batch to execute after the previous batch's signature-verified gate"), "internal/server/fleet_reissuance_worker.go:issuanceDispatcher.handleFleetReissuanceBatch"),
	evidence("ITSMTicket", "status", observationPredicate, "internal/api/itsm.go:toITSMTicketResponse"),
	evidence("Identity", "status", eventProjectionPredicate, "internal/orchestrator/orchestrator.go:Orchestrator.Transition"),
	evidence("IncidentExecution", "status", eventProjectionPredicate, "internal/orchestrator/commands.go:Orchestrator.RecordIncidentExecution"),
	evidence("IssuanceRequest", "status", eventProjectionPredicate, "internal/orchestrator/issuance_request.go:Orchestrator.DecideIssuanceRequest"),
	evidence("KubernetesSecretOperatorCRD", "status", observationPredicate, "internal/api/secrets_posture.go:buildKubernetesSecretOperator"),
	evidence("MDMTraceStep", "outcome", predicate(evidenceObservation, "ok/failed require the matching durable SCEP, issuance, installation, or renewal evidence event; missing stage evidence remains pending or unknown"), "internal/api/mdm_devices.go:API.buildDeviceTrace"),
	evidence("MachineSession", "status", eventProjectionPredicate, "internal/store/machine_session.go:Store.ApplyMachineSessionStartedTx"),
	evidence("Member", "status", eventProjectionPredicate, "internal/orchestrator/commands.go:Orchestrator.UpsertTenantMember"),
	evidence("NHIComplianceControl", "status", attestationPredicate, "internal/api/nhi_compliance.go:buildNHIComplianceControls"),
	evidence("NHIExposureFinding", "status", observationPredicate, "internal/api/nhi_exposure_posture.go:nhiExposureFindingForItem"),
	evidence("NHIInventoryItem", "status", observationPredicate, "internal/api/nhi_inventory.go:API.nhiInventory"),
	evidence("NHIOverPrivilegeFinding", "status", observationPredicate, "internal/api/nhi_posture.go:nhiOverPrivilegeForItem"),
	evidence("NHIPolicyComplianceFinding", "status", observationPredicate, "internal/api/nhi_policy_compliance.go:nhiPolicyComplianceForItem"),
	evidence("NHIReviewCampaign", "status", eventProjectionPredicate, "internal/orchestrator/nhi_access_review.go:Orchestrator.StartNHIReviewCampaign"),
	evidence("NHIReviewItem", "status", eventProjectionPredicate, "internal/orchestrator/nhi_access_review.go:Orchestrator.DecideNHIReviewItem"),
	evidence("NHIStaleFinding", "status", observationPredicate, "internal/api/nhi_stale_posture.go:nhiStaleFindingForItem"),
	evidence("NHIStaticFinding", "status", observationPredicate, "internal/api/nhi_static_posture.go:nhiStaticFindingForItem"),
	evidence("Notification", "status", observationPredicate, "internal/api/notifications.go:toNotificationResponse"),
	evidence("NotificationChannelTest", "status", workflowPredicate, "internal/api/notifications.go:notificationChannelTestOperationResponse"),
	evidence("OutboxReconciliationConflict", "status", predicate(evidenceEventProjection, "quarantined requires a typed exact-command collision, an immutable conflict event, and a projection that binds both safe command digests while the candidate remains unexecuted"), "internal/orchestrator/orchestrator.go:Orchestrator.quarantineOutboxReconciliationConflict"),
	evidence("OwnerRemediationAction", "status", eventProjectionPredicate, "internal/api/owner_remediation.go:ownerRemediationActionFromFinding"),
	evidence("OwnerRemediationQueue", "status", eventProjectionPredicate, "internal/api/owner_remediation.go:ownerRemediationSummaryFor"),
	evidence("OwnerRemediationRun", "status", eventProjectionPredicate, "internal/api/owner_remediation.go:API.acceptedOwnerRemediationRuns"),
	evidence("PAMSession", "status", observationPredicate, "internal/api/pam.go:API.listPAMSessions"),
	evidence("PendingApprovalRequest", "status", operationApprovalPredicate, "internal/server/approval_gate.go:approvalRequestRecord"),
	evidence("PQCMigrationCampaign", "status", eventProjectionPredicate, "ee/pqcmigration/server.go:pqcMigrationService.Progress"),
	evidence("PQCMigrationCampaignReadinessRequest", "status", observationPredicate, "ee/pqcmigration/server.go:pqcMigrationService.PlanPreview"),
	evidence("PolicyVersion", "status", eventProjectionPredicate, "internal/api/policy_versions.go:API.policyVersions"),
	evidence("Problem", "status", predicate(evidenceProtocol, "the integer is the HTTP response code written with the RFC 9457 problem document, not a workflow verdict"), "internal/api/problem/problem.go:Problem.Write"),
	evidence("RemediationPlaybook", "status", configurationPredicate, "internal/api/remediation_playbooks.go:remediationPlaybookCatalog"),
	evidence("RemediationPlaybookCatalog", "status", configurationPredicate, "internal/api/remediation_playbooks.go:remediationPlaybookCatalog"),
	evidence("RemediationPlaybookRun", "status", eventProjectionPredicate, "internal/store/remediation_playbooks.go:Store.ApplyRemediationPlaybookRunRecordedTx"),
	evidence("ResponseIntegrationDispatch", "status", observationPredicate, "internal/api/response_integrations.go:toResponseIntegrationDispatchResponse"),
	evidence("ResponseIntegrationQueuedDestination", "status", workflowPredicate, "internal/api/response_integrations.go:API.responseIntegrationDestinationCommand"),
	evidence("RogueCertificateFinding", "status", observationPredicate, "internal/api/rogue_certificates.go:rogueCertificateFindingForCertificate"),
	evidence("RotationRun", "status", eventProjectionPredicate, "internal/store/connector_lifecycle.go:Store.ApplyRotationRunRecordedTx"),
	evidence("SSHHostRetirement", "status", eventProjectionPredicate, "internal/api/ssh_workflow.go:API.retireSSHHost"),
	evidence("SSHTrustRollout", "status", eventProjectionPredicate, "internal/api/ssh_workflow.go:API.getSSHStatus"),
	evidence("SSHTrustRolloutRequest", "status", workflowPredicate, "internal/api/ssh_workflow.go:API.recordSSHTrustRollout"),
	evidence("SecretApproval", "status", operationApprovalPredicate, "internal/api/approvals.go:approvalResponseFor"),
	evidence("SecretRepositoryWebhookReceipt", "status", protocolPredicate, "internal/api/secrets_scanning.go:API.receiveSecretRepoWebhook"),
	evidence("SecretRotationScheduleRun", "status", eventProjectionPredicate, "internal/orchestrator/secret_rotation.go:Orchestrator.RecordSecretRotationScheduleRun"),
	evidence("SecretSyncWorkloadIdentitySource", "status", observationPredicate, "internal/api/secret_sync_workload_identity.go:toSecretSyncWorkloadIdentitySourceResponse"),
	evidence("SecretWorkloadInjectionCRD", "status", observationPredicate, "internal/api/secrets_posture.go:buildSecretWorkloadInjection"),
	evidence("ThirdPartySecretScanReceipt", "status", observationPredicate, "internal/api/secrets_scanning.go:API.ingestThirdPartySecretScan"),
	evidence("UnownedIdentity", "status", observationPredicate, "internal/api/owners_unowned.go:API.listUnownedIdentities"),
}
