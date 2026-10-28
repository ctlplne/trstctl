// SPDX-License-Identifier: BUSL-1.1

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
	evidence("SSHTrustFleetRollout", "state", predicate(evidenceObservation, "pending requires queued exact-host intents; verified requires every ready host's matching immutable signed receipt with CA/effective-config readback and validation/reload/health; skipped hosts never receive jobs; failure or checked rollback remains attention_required. Read rows without matching source evidence are unavailable, never verified."), "internal/server/ssh_trust_fleet_evidence.go:sshTrustFleetService.bindSSHTrustFleetView"),
	evidence("SSHTrustFleetHost", "state", predicate(evidenceObservation, "queued and skipped preserve the exact approved roster. verified, failed and refused require the matching tenant, host, job, attempt and immutable observation source; unsigned or fabricated projection completion is unavailable."), "internal/server/ssh_trust_fleet_evidence.go:sshTrustFleetService.bindSSHTrustFleetView"),
	evidence("SSHTrustFleetReport", "state", predicate(evidenceObservation, "The host worker refuses without writes unless local opt-in, confirmation, staged CA, current policy, exact identity and deadline agree. verified requires independent CA/effective-path readback and validation/reload/health. The control plane verifies the exact mTLS receipt signature and claimed attempt before append."), "internal/server/ssh_trust_fleet_result.go:agentService.recordSSHTrustFleetResult"),
	evidence("SSHTrustFleetReport", "rollback", predicate(evidenceObservation, "verified restoration requires exact prior file byte readback and fresh validation, reload and health under bounded cleanup. A failed change remains failed even when recovery was verified; not_available and failed never imply safe restoration."), "internal/agent/sshtrust/observed.go:Applier.AddCATrustObserved"),
	evidence("SSHTrustFleetApproval", "status", predicate(evidenceEventProjection, "Copied from the tenant approval request and distinct reviewer decisions for the exact fleet effect. No preview or approval status claims a host mutation; dispatch and signed host observations are separate."), "internal/server/ssh_trust_fleet.go:sshTrustFleetService.RequestSSHTrustFleetApproval"),
	evidence("CMDBCertificateExport", "status", predicate(evidenceObservation, "pending, processing, and failed describe the exact tenant-bound export command's outbox attempt; verified requires its immutable canonical receipt after ServiceNow IRE accepted the fixed certificate class and an independent GET matched every exported field, binding the operation, certificate fingerprint, operator write binding, CI ID, lifecycle state, and values digest. A missing queue row without a receipt is recovery_required. The receipt records the verified effect at checked_at; it does not claim later lifecycle changes were exported automatically"), "internal/server/cmdb_certificate_export.go:certificateCIExporter.Status"),
	evidence("ACMEDNS01CAAPolicyEvidence", "status", predicate(evidenceObservation, "allowed, denied, unrestricted, and lookup_failed are derived from the authoritative live DNS CAA lookup used by the production preflight; not_configured is emitted only when the tenant provider configuration names no CAA issuer domain, and lookup failure remains a fail-closed result rather than an authorization"), "internal/api/acme_dns01.go:API.evaluateDNS01Preflight"),
	evidence("ACMEDNS01PreflightCheck", "status", observationPredicate, "internal/api/acme_dns01.go:API.evaluateDNS01Preflight"),
	evidence("ACMEDNS01QualificationRun", "status", predicate(evidenceObservation, "passed requires delivered publish and cleanup outbox work plus successful lookup through the served ACME resolver; recovery_required requires a failed cleanup row after the real publish attempt; failed preserves a non-secret failure category rather than a raw worker error"), "internal/server/acme_dns01_qualification.go:Server.ListACMEDNS01QualificationRuns"),
	evidence("AccessChangeRequest", "status", eventProjectionPredicate, "internal/orchestrator/access_change_request.go:Orchestrator.CreateAccessChangeRequest"),
	evidence("Agent", "status", observationPredicate, "internal/api/agents.go:toAgentResponse"),
	evidence("AgentUpgradeCampaign", "status", eventProjectionPredicate, "internal/orchestrator/agent_upgrade.go:Orchestrator.OpenAgentUpgradeCampaign"),
	evidence("Approval", "status", operationApprovalPredicate, "internal/api/approvals.go:approvalResponseFor"),
	evidence("ApprovalDecision", "status", operationApprovalPredicate, "internal/api/approvals.go:approvalResponseFor"),
	evidence("ArchiveLegalHold", "status", predicate(evidenceEventProjection, "pending requires an immutable archive.legal_hold.placed event, or a report legal hold event naming the object, with the same-transaction outbox row that sets the S3 legal hold; applied and released require the outbox delivery to have set or cleared that hold and read the bucket's legal hold back in that state before it appends archive.legal_hold.recorded; release_pending requires the release event and its outbox row; failed preserves why the bucket could not take the hold. None of these values claims anything about the object's retention period or about copies outside the bucket"), "internal/server/archive_legal_hold.go:archiveLegalHoldDelivery.Deliver"),
	evidence("AuditFeed", "status", predicate(evidenceEventProjection, "configured, queued, delivered, and failed are derived only from the tenant's immutable audit.feed.* events and their projection; delivered additionally requires the exact collector receipt while failed preserves the terminal delivery error and lag"), "internal/store/audit_feed.go:AuditFeed.EffectiveStatus"),
	evidence("BreakglassCeremony", "status", eventProjectionPredicate, "internal/api/breakglass.go:API.startBreakglassIssueCeremony"),
	evidence("BulkRevokeItem", "status", workflowPredicate, "internal/api/bulk_revoke.go:API.bulkRevoke"),
	evidence("BulkRevokeRequest", "status", workflowPredicate, "internal/api/bulk_revoke.go:API.bulkRevoke"),
	evidence("CAAuthority", "status", eventProjectionPredicate, "internal/api/ca_hierarchy.go:API.listCAAuthorities"),
	evidence("CACeremonyPlanAuthority", "status", eventProjectionPredicate, "internal/server/ca_hierarchy.go:caCeremonyPlanAuthority"),
	evidence("CAAuthorityRotationIssuer", "status", eventProjectionPredicate, "internal/api/ca_hierarchy.go:API.rotateCAAuthority"),
	evidence("CADiscoveryItem", "status", observationPredicate, "internal/api/ca_discovery.go:API.listCADiscoveryInventory"),
	evidence("CAKeyCeremony", "status", eventProjectionPredicate, "internal/api/ca_hierarchy.go:API.createCACeremony"),
	evidence("Certificate", "status", eventProjectionPredicate, "internal/projections/projections.go:Projector.Apply"),
	evidence("CertificateDERRecovery", "outcome", predicate(evidenceObservation, "recovered requires certificate bytes read from a mint event of the tenant's own CA or from a TLS handshake with the row's recorded host:port whose SHA-256 equals the row's fingerprint, appended as an immutable certificate.der.recovered event that the projection checks again and applies only to a row holding no bytes; already_held, not_found, mismatch and unreachable attach nothing"), "internal/server/certificate_der_recovery.go:Server.RecoverCertificateDER"),
	evidence("CertificateHealthItem", "status", observationPredicate, "internal/api/certificates.go:toCertificateHealthDashboard"),
	evidence("CodeSigningIdentity", "status", eventProjectionPredicate, "internal/api/codesign_identities.go:API.listCodeSigningIdentities"),
	evidence("ConnectorDelivery", "status", predicate(evidenceObservation, "the connector receipt registry binds each value to queued, contacted, mutated, or independently verified evidence"), "internal/orchestrator/commands.go:Orchestrator.RecordConnectorDelivery"),
	evidence("KeyCompromiseRevocationAttempt", "status", predicate(evidenceWorkflow, "pending requires the exact revocation.publish outbox row from the retained identity.revoked command; processing records a dispatcher claim; delivered requires its completed CA call and is recovered after outbox GC only from the exact durable worker completion event; failed preserves the terminal dispatcher result; evidence_unavailable means a historical outbox row expired without a worker receipt and never implies CA success. None of these values alone proves a signed CRL, OCSP response, or relying-party rejection"), "internal/orchestrator/key_compromise.go:Orchestrator.KeyCompromiseStatus"),
	evidence("ComplianceReportRun", "status", predicate(evidenceEventProjection, "queued requires a durable tenant event for the exact schedule and due time; retrying and failed require event-backed bounded attempts and sanitized failure codes; completed additionally requires signer-verified exact bytes in the private archive bound to the event digest, and never implies delivery outside the local control plane"), "internal/orchestrator/compliance_report_run.go:Orchestrator.RecordComplianceReportRun"),
	evidence("CryptoReadinessAction", "status", predicate(evidenceEventProjection, "open and closed are copied only from the tenant's event-projected PQC campaign row, and the action is served on this dataset only when its finding carries an exact crypto-readiness row digest; stale topology remains separately visible and blocks further mutation"), "internal/store/pqc_migration_campaign.go:Store.ListCryptoReadinessActions"),
	evidence("CryptoRiskDeadline", "status", predicate(evidenceConfiguration, "derived only from the key's recorded algorithm and size against the NIST IR 8547 initial-public-draft tables encoded in the report, the key's weak or distrusted verdict, and the report's generation time; it never claims a key was replaced or that a CNSA 2.0 milestone applies"), "internal/cryptorisk/deadline.go:DeadlineFor"),
	evidence("CryptoRiskPlanAction", "status", predicate(evidenceEventProjection, "copied only from the crypto-readiness dataset's event-projected PQC campaign action bound to the key's crypto asset; stale marks an action whose graph row changed since it started"), "internal/cryptorisk/report.go:readinessParts"),
	evidence("CTMonitoringLog", "status", predicate(evidenceEventProjection, "never means no immutable completion result exists for the active log; succeeded and failed require the matching bounded per-log result in a schema-v2 discovery.run.completed event, projected only while that log remains in the tenant's current CT source configuration"), "internal/store/ctmonitor.go:Store.ApplyCTLogPollResultFromEventTx"),
	evidence("DRDrill", "outcome", predicate(evidenceObservation, "restored requires the delivered full backup set to restore into isolated ephemeral data and messaging targets; failed and skipped record why that predicate was not met"), "internal/server/drill.go:RunRestoreDrill"),
	evidence("DeploymentKEKRotation", "status", predicate(evidenceEventProjection, "running requires an immutable deployment.kek.rotation_started or rotation_progressed event in the operator tenant's history that records the next generation's wrapped key; failed requires a rotation_failed event naming the step that stopped; completed requires a rotation_completed event, which the rotation appends only after a verify pass read every stored deployment-KEK data key and sealed file back and found none under the previous generation. None of these values claims that backups, archives, or exports taken before the rotation were re-wrapped"), "internal/projections/deployment_kek.go:Projector.applyDeploymentKEKSnapshotTx"),
	evidence("DiscoveryCoverageClass", "status", observationPredicate, "internal/api/discovery.go:API.getDiscoveryCoverage"),
	evidence("DiscoveryRun", "status", eventProjectionPredicate, "internal/orchestrator/discovery.go:Orchestrator.CompleteDiscoveryRun"),
	evidence("DiscoverySegmentCoverage", "status", observationPredicate, "internal/api/discovery.go:API.getDiscoveryCoverage"),
	evidence("EdgeDelegation", "status", eventProjectionPredicate, "internal/api/edge_delegation.go:API.listEdgeDelegations"),
	evidence("EnrollmentDiagnosticVerification", "status", predicate(evidenceEventProjection, "queued requires an immutable tenant-scoped enrollment.diagnostic.verification.queued event plus the same-transaction endpoint-verification outbox command; it is only an action receipt and never claims that the endpoint was contacted or fixed"), "internal/orchestrator/enrollment_diagnostics.go:Orchestrator.QueueEnrollmentDiagnosticVerification"),
	evidence("EndpointRecoveryCheck", "status", predicate(evidenceEventProjection, "queued requires an immutable endpoint.recovery_check.requested event and the same-transaction outbox row pinned to the target's enrolled host agent; checked requires that agent's signed job receipt whose evidence digest binds the report, validated against the queued check before endpoint.recovery_check.checked is appended; failed requires the agent's signed refusal, recorded with a closed reason. checked reports what the host profile pins and what one local probe saw; it never claims the listener was restored"), "internal/server/endpoint_recovery_check_result.go:agentService.recordEndpointRecoveryCheckResult"),
	evidence("EndpointVerification", "status", predicate(evidenceObservation, "verified/diverged require a live listener handshake receipt; unreachable/not_checked explicitly carry no positive verdict"), "internal/api/endpoint_verification.go:endpointVerificationStatus"),
	evidence("EphemeralApproval", "status", operationApprovalPredicate, "internal/server/ephemeral.go:ephemeralIssuerService.ApproveEphemeralCredential"),
	evidence("ExternalCA", "status", observationPredicate, "internal/api/external_ca.go:API.listExternalCAs"),
	evidence("FIPSCustodyValidationCertificate", "status", attestationPredicate, "internal/compliance/fips.go:FIPSCustodyValidationCertificates"),
	evidence("FleetReissuanceBatch", "health_gate", predicate(evidenceObservation, "passed requires every member's lease-bound agent trust, live-serving, and exact predecessor-revocation verdict to be verified; any signed failure is failed and missing evidence remains not_evaluated"), "internal/server/incident_migration_sync.go:incidentWaveGate"),
	evidence("FleetReissuanceBatch", "status", predicate(evidenceWorkflow, "executed requires the H2 cohort to pass signed trust and live-serving gates and verify exact predecessor revocation; failed requires a signed failure and completed current-cohort rollback"), "internal/server/incident_migration_sync.go:incidentWaveStatus"),
	evidence("FleetReissuanceHealthGate", "status", predicate(evidenceObservation, "passed/failed require a named evidence evaluation; no receipt set remains not_evaluated"), "internal/api/incident_fleet_reissuance.go:evaluateFleetDeploymentGate"),
	evidence("FleetReissuanceRun", "status", predicate(evidenceEventProjection, "the value mirrors the persisted event-sourced H2 aggregate; executed requires all signed gates plus exact predecessor revocations and rolled_back requires the failed current cohort's signed rollback evidence"), "internal/server/incident_migration_sync.go:syncIncidentMigrationState"),
	evidence("ITSMTicket", "status", observationPredicate, "internal/api/itsm.go:toITSMTicketResponse"),
	evidence("Identity", "status", eventProjectionPredicate, "internal/orchestrator/orchestrator.go:Orchestrator.Transition"),
	evidence("IncidentExecution", "status", eventProjectionPredicate, "internal/orchestrator/commands.go:Orchestrator.RecordIncidentExecution"),
	evidence("IssuanceRequest", "status", eventProjectionPredicate, "internal/orchestrator/issuance_request.go:Orchestrator.DecideIssuanceRequest"),
	evidence("KubernetesSecretOperatorCRD", "status", observationPredicate, "internal/api/secrets_posture.go:buildKubernetesSecretOperator"),
	evidence("LifecycleAutomationScheduler", "status", predicate(evidenceConfiguration, "running requires the lifecycle scheduler, store, orchestrator, and renewal threshold to be configured while the current maintenance window permits new starts; deferred requires an active maintenance-window deferral; disabled means at least one required scheduler prerequisite is absent, and none of these values claims that a renewal was executed"), "internal/server/lifecycle_automation_plan.go:Server.LifecycleAutomationPlan"),
	evidence("MCPToolResult", "outcome", predicate(evidenceWorkflow, "queued requires the identity transition route, entered with the caller's own credentials through the lifecycle gate, to have accepted the transition, which records it and queues its CA call in the outbox; proposed requires that route's dual-control refusal naming the exact approval request it recorded, with nothing executed; neither value claims that a certificate was issued"), "internal/api/aisurface_handlers.go:API.mcpCallWrite"),
	evidence("MDMTraceStep", "outcome", predicate(evidenceObservation, "ok/failed require the matching durable SCEP, issuance, installation, or renewal evidence event; missing stage evidence remains pending or unknown"), "internal/api/mdm_devices.go:API.buildDeviceTrace"),
	evidence("MigrationRun", "status", predicate(evidenceEventProjection, "the status is the immutable H2 aggregate state produced by signed trust, live-serving, exact revocation, and rollback observations; complete and rolled_back are impossible while a required cohort verdict is absent"), "internal/migration/run.go:Observe"),
	evidence("MigrationRunStartPending", "status", operationApprovalPredicate, "internal/api/migration.go:API.startMigrationRun"),
	evidence("MachineSession", "status", eventProjectionPredicate, "internal/store/machine_session.go:Store.ApplyMachineSessionStartedTx"),
	evidence("ManagedKeyApprovalProblem", "status", predicate(evidenceProtocol, "the integer is the HTTP response code of the RFC 9457 refusal; approval_request_id and intent_digest appear only when the exact managed-key command opened a still-pending request"), "internal/api/problem/problem.go:Problem.Write"),
	evidence("ManagedKeyOperation", "status", predicate(evidenceEventProjection, "queued requires an immutable tenant-scoped managed-key command event and same-transaction provider outbox intent; completed requires the matching provider-result event; failed requires a matching terminal failure event. A completed command does not by itself prove current provider custody, which needs a separate fresh signature challenge"), "internal/projections/managed_keys.go:Projector.applyManagedKeyTx"),
	evidence("Member", "status", eventProjectionPredicate, "internal/orchestrator/commands.go:Orchestrator.UpsertTenantMember"),
	evidence("NHIComplianceControl", "status", attestationPredicate, "internal/api/nhi_compliance.go:buildNHIComplianceControls"),
	evidence("NHIExposureFinding", "status", observationPredicate, "internal/api/nhi_exposure_posture.go:nhiExposureFindingForItem"),
	evidence("NHIInventoryItem", "status", observationPredicate, "internal/api/nhi_inventory.go:API.nhiInventory"),
	evidence("NHIOverPrivilegeFinding", "status", observationPredicate, "internal/api/nhi_posture.go:nhiOverPrivilegeForItem"),
	evidence("NHIPolicyComplianceFinding", "status", observationPredicate, "internal/api/nhi_policy_compliance.go:nhiPolicyComplianceForItem"),
	evidence("NHIPostureAutomationItem", "status", observationPredicate, "internal/api/nhi_posture_automation.go:API.nhiPostureAutomationPlan"),
	evidence("NHIPostureAutomationRun", "status", eventProjectionPredicate, "internal/store/remediation_playbooks.go:Store.ApplyRemediationPlaybookRunRecordedTx"),
	evidence("NHIExposureReachability", "status", observationPredicate, "internal/api/nhi_exposure_probe.go:nhiExposureReachabilityStatus"),
	evidence("NHIExposureReachabilityProbe", "outcome", predicate(evidenceObservation, "tls_certificate/unparseable_certificate/listener_without_tls/not_public/unreachable are classified from the network relay's signed probe transcript: a completed handshake with a parsed or unparseable leaf, a handshake-stage failure after the connection was accepted, the SSRF guard's refusal of a non-public address, or a failed dial"), "internal/orchestrator/exposure_probe.go:exposureProbeOutcome"),
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
	evidence("PAMApprovalRequest", "status", operationApprovalPredicate, "internal/server/pam.go:pamService.RequestPAMSession"),
	evidence("PAMRequestProgress", "status", predicate(evidenceEventProjection, "pending/approved/denied/consumed come from the tenant-scoped operation-approval event projection; an unprojected elapsed deadline is conservatively reported as expired and never makes an approval reusable"), "internal/server/pam.go:pamService.GetPAMRequestProgress"),
	evidence("PAMSession", "status", observationPredicate, "internal/api/pam.go:API.listPAMSessions"),
	evidence("PendingApprovalRequest", "status", operationApprovalPredicate, "internal/server/approval_gate.go:approvalRequestRecord"),
	evidence("PQCMigrationCampaign", "status", eventProjectionPredicate, "internal/pqcmigration/server.go:pqcMigrationService.Progress"),
	evidence("PQCMigrationCampaignReadinessRequest", "status", observationPredicate, "internal/pqcmigration/server.go:pqcMigrationService.PlanPreview"),
	evidence("PQCPilot", "status", predicate(evidenceEventProjection, "running/halted/completed are rebuilt from pqc.pilot.wave_assessed events whose verdict the compat-lab rules derived from the relay's signed transcripts"), "internal/orchestrator/pqc_pilot.go:Orchestrator.RecordPQCPilotWave"),
	evidence("PQCPilotWave", "status", eventProjectionPredicate, "internal/store/pqc_pilot.go:Store.ApplyPQCPilotWaveAssessedTx"),
	evidence("AssuranceCredential", "status", predicate(evidenceEventProjection, "copied from the tenant's certificate inventory row, which the certificate.recorded, renewal and revocation projections rebuild from immutable events; the assurance record restates it and claims nothing beyond it"), "internal/assurance/record.go:Build"),
	evidence("AssuranceDeployment", "status", predicate(evidenceWorkflow, "copied from the connector delivery receipt the delivery workflow recorded for this certificate's fingerprint; basis recorded says no endpoint observation is implied by it"), "internal/assurance/record.go:Build"),
	evidence("AssuranceVerification", "outcome", predicate(evidenceObservation, "verified and verify_failed are copied from verification receipts (signed_observation when the reporting agent's signed job receipt verified); verified, mismatch and unreachable from the latest endpoint observation per listener and vantage, which names the served fingerprint and which comparisons ran"), "internal/assurance/record.go:Build"),
	evidence("AssuranceExternalObservation", "verdict", predicate(evidenceObservation, "copied from the external observation as recorded: match and mismatch compare the fingerprint the observer reported with what trstctl's newest endpoint verification expected at that address when the report arrived; unreachable is the observer's own report; unexpected means no expectation existed"), "internal/assurance/record.go:Build"),
	evidence("Observation", "verdict", predicate(evidenceObservation, "derived when the report arrives from the observer's reported reachability and served fingerprint against the expectation of trstctl's newest endpoint verification at that address; trstctl does not probe the endpoint itself for this verdict"), "internal/orchestrator/external_observation.go:Orchestrator.RecordObservation"),
	evidence("AssuranceLink", "status", predicate(evidenceEventProjection, "copied from the related certificate's inventory row, linked by its replaces_id projection; a link asserts the replacement relation the renewal projection recorded"), "internal/assurance/record.go:Build"),
	evidence("AssuranceRenewalRun", "status", predicate(evidenceWorkflow, "copied from the lifecycle rotation run the renewal workflow recorded, naming its predecessor and successor fingerprints"), "internal/assurance/record.go:Build"),
	evidence("ValidityReadinessCertificateStep", "verdict", predicate(evidenceConfiguration, "renews requires a scheduled certificate — the served or evidence-bound certificate of an identity in the scheduler's own renewable inventory — with automatic renewal enabled, a deploy receipt whose served certificate was read back, no renewal hold or approval gate, and for public TLS a renewal lifetime within the step's maximum; at_risk and manual name the reasons that withheld renews; the assessment contacts no target and claims no future renewal outcome"), "internal/tlsvalidity/readiness.go:evaluateCertificate"),
	evidence("PQCPilotWave", "verdict", predicate(evidenceObservation, "the verdict is compat-lab Assess over the relay's signed handshake transcripts accumulated through this wave; a wave never probed carries none"), "internal/orchestrator/pqc_pilot.go:Orchestrator.RecordPQCPilotWave"),
	evidence("PQCPilotResult", "outcome", predicate(evidenceObservation, "negotiated/rejected/unreachable are classified from the relay's signed probe transcript: reached with the exact leaf, reached but refused or served another leaf, or a failed dial"), "internal/orchestrator/pqc_pilot.go:ClassifyPQCPilotTranscript"),
	evidence("PolicyVersion", "status", eventProjectionPredicate, "internal/api/policy_versions.go:API.policyVersions"),
	evidence("Problem", "status", predicate(evidenceProtocol, "the integer is the HTTP response code written with the RFC 9457 problem document, not a workflow verdict"), "internal/api/problem/problem.go:Problem.Write"),
	evidence("RemediationPlaybook", "status", configurationPredicate, "internal/api/remediation_playbooks.go:remediationPlaybookCatalog"),
	evidence("RemediationPlaybookCatalog", "status", configurationPredicate, "internal/api/remediation_playbooks.go:remediationPlaybookCatalog"),
	evidence("RemediationPlaybookRun", "status", eventProjectionPredicate, "internal/store/remediation_playbooks.go:Store.ApplyRemediationPlaybookRunRecordedTx"),
	evidence("SSHKRLHost", "outcome", predicate(evidenceObservation, "the host agent read the installed digest and version back from its sshd RevokedKeys file after the attempt and signed the receipt with its certificate key; the control plane verified that signature against the exact mTLS peer certificate, the agent's host role, its own tenant, freshness, and monotonic issue time before projecting it, and a missing or stale receipt is reported as stale rather than current"), "cmd/trstctl-agent/sshkrl_watch.go:sshKRLReceiptFor"),
	evidence("RevocationCacheStatus", "status", predicate(evidenceObservation, "fresh requires the relay to validate issuer identity, object signature, serial/nonce where applicable, and the signed time window; the control plane then verifies the network relay certificate signature before projecting it, while stale, empty, error, and unobserved remain distinct"), "internal/agent/revcache/manager.go:Manager.Statuses"),
	evidence("RevocationEndpointHealth", "status", predicate(evidenceObservation, "fresh requires a lease-bound agent signature plus successful CRL or OCSP signature, status, and freshness verification; stale, invalid, and unreachable preserve the exact failed check, while a missing observation is not projected as healthy"), "internal/projections/projections.go:Projector.Apply"),
	evidence("ResponseIntegrationDispatch", "status", observationPredicate, "internal/api/response_integrations.go:toResponseIntegrationDispatchResponse"),
	evidence("ResponseIntegrationQueuedDestination", "status", workflowPredicate, "internal/api/response_integrations.go:API.responseIntegrationDestinationCommand"),
	// A52: the ACME admin views serve the protocol server's registration-bound
	// state, which is rebuilt from the tenant's acme.* state events; the live
	// handlers append the same events before mutating the view.
	evidence("ACMEAccount", "status", eventProjectionPredicate, "internal/protocols/acme/state.go:Server.applyStateEventLocked"),
	evidence("ACMEAuthorization", "status", eventProjectionPredicate, "internal/protocols/acme/state.go:Server.applyStateEventLocked"),
	evidence("ACMEChallenge", "status", eventProjectionPredicate, "internal/protocols/acme/state.go:Server.applyStateEventLocked"),
	evidence("ACMEOrder", "status", eventProjectionPredicate, "internal/protocols/acme/state.go:Server.applyStateEventLocked"),
	evidence("RogueCertificateFinding", "status", observationPredicate, "internal/api/rogue_certificates.go:rogueCertificateFindingForCertificate"),
	evidence("RotationRun", "status", eventProjectionPredicate, "internal/store/connector_lifecycle.go:Store.ApplyRotationRunRecordedTx"),
	evidence("SSHHostRetirement", "status", eventProjectionPredicate, "internal/api/ssh_workflow.go:API.retireSSHHost"),
	evidence("SSHTrustRollout", "status", eventProjectionPredicate, "internal/api/ssh_workflow.go:API.getSSHStatus"),
	evidence("SSHTrustRolloutRequest", "status", workflowPredicate, "internal/api/ssh_workflow.go:API.recordSSHTrustRollout"),
	evidence("SecretApproval", "status", operationApprovalPredicate, "internal/api/approvals.go:approvalResponseFor"),
	evidence("SecretRepositoryWebhookReceipt", "status", protocolPredicate, "internal/api/secrets_scanning.go:API.receiveSecretRepoWebhook"),
	evidence("SecretRotationScheduleRun", "status", eventProjectionPredicate, "internal/orchestrator/secret_rotation.go:Orchestrator.RecordSecretRotationScheduleRun"),
	evidence("SecretSyncJob", "status", predicate(evidenceEventProjection, "pending requires the tenant's immutable secret.sync.queued event; delivered or failed requires the exact canonical terminal event projected for that job. The status does not prove independent external readback or relying-party use"), "internal/store/secret_sync_job.go:Store.ApplySecretSyncTerminalEventTx"),
	evidence("SecretSyncReconcileResult", "outcome", predicate(evidenceObservation, "delivered requires an independent receiver readback that matched this command's value, or a recorded operator attestation naming the operator, before the delivered event is appended; failed requires a readback or attestation proving the receiver never held this command's value, recorded as reconciled failure authority; settled requires the same proof for an already delivered multi-start command and is recorded as one retained secret.sync.receiver_settled event; terminal means nothing was left to reconcile. unknown, diverged and not_started are refused with 409 and change nothing"), "internal/server/secret_sync_reconcile.go:secretIntegrationOutboxDispatcher.ReconcileSecretSyncJob"),
	evidence("SecretSyncWorkloadIdentitySource", "status", observationPredicate, "internal/api/secret_sync_workload_identity.go:toSecretSyncWorkloadIdentitySourceResponse"),
	evidence("SecretWorkloadInjectionCRD", "status", observationPredicate, "internal/api/secrets_posture.go:buildSecretWorkloadInjection"),
	evidence("ThirdPartySecretScanReceipt", "status", observationPredicate, "internal/api/secrets_scanning.go:API.ingestThirdPartySecretScan"),
	evidence("UnownedIdentity", "status", observationPredicate, "internal/api/owners_unowned.go:API.listUnownedIdentities"),
	evidence("UrgentRiskSummary", "status", predicate(evidenceObservation, "complete is written only after both tenant-scoped credential-risk and contextual-priority readers return successfully; either read failure returns an API error, so a partial projection cannot become a safe zero"), "internal/api/risk.go:API.listContextualRiskPriorities"),
}
