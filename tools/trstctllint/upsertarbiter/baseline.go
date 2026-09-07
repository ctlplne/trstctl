// SPDX-License-Identifier: MPL-2.0

package upsertarbiter

// reviewedUpserts lists the pre-existing upsert sites whose tables carry a second
// unique index and that neither lock nor retry (OPP-C01 closure sweep, 2026-09-07).
// They are the DP2-043/DP2-046 family still owed a fix; each is keyed by
// repo-relative file and enclosing function so a NEW site fails closed, and
// TestReviewedBaselineIsNotStale fails when an entry no longer needs listing.
var reviewedUpserts = map[string]map[string]bool{
	"internal/store/agent.go": {
		"ApplyAgentCertRenewedTx": true,
		"ApplyAgentHeartbeatTx":   true,
		"ApplyAgentOffboardedTx":  true,
	},
	"internal/store/api_token.go": {
		"ApplyAPITokenCreatedTx": true,
	},
	"internal/store/audit_feed.go": {
		"ApplyAuditFeedBatchQueuedTx": true,
		"ApplyAuditFeedConfiguredTx":  true,
	},
	"internal/store/ca.go": {
		"ApplyKeyCeremonyApprovedTx": true,
		"applyCAAuthorityUpsertTx":   true,
	},
	"internal/store/compliance_report.go": {
		"ApplyComplianceReportScheduleUpsertedTx": true,
	},
	"internal/store/cryptoasset.go": {
		"ApplyCryptoAssetObservedTx": true,
	},
	"internal/store/ctmonitor_reconcile.go": {
		"reconcileCTMonitoringFromSourcesTx": true,
	},
	"internal/store/dynamic_secret_epoch.go": {
		"ResolveDynamicSecretPendingTenantEpochTx": true,
		"ensureDynamicSecretTenantEpochTx":         true,
	},
	"internal/store/dynamic_secret_lease.go": {
		"ApplyDynamicSecretLeasePendingTx": true,
	},
	"internal/store/edge_delegation.go": {
		"ApplyEdgeDelegationIssuedTx": true,
	},
	"internal/store/enrollment_diagnostics.go": {
		"ApplyEnrollmentDiagnosticObservedTx": true,
	},
	"internal/store/mdm_correlation.go": {
		"ApplyMDMDeviceCorrelatedTx": true,
	},
	"internal/store/operation_approvals.go": {
		"ApplyOperationApprovalDecisionTx":  true,
		"ApplyOperationApprovalRequestedTx": true,
	},
	"internal/store/outbox_reconciliation_conflicts.go": {
		"ApplyOutboxReconciliationConflictRecordedTx": true,
	},
	"internal/store/projection.go": {
		"ApplyAgentUpgradeCampaignOpenedTx": true,
		"ApplyCMDBScheduleConfiguredTx":     true,
		"ApplyOwnershipReconciledTx":        true,
		"ApplyProfileVersionTx":             true,
	},
	"internal/store/remediation_playbooks.go": {
		"ApplyRemediationPlaybookRunRecordedTx": true,
	},
	"internal/store/secret_rotation_schedule.go": {
		"ApplySecretRotationScheduleUpsertedTx": true,
	},
	"internal/store/secret_sync_job.go": {
		"ResolveSecretSyncQueuedTenantEpochTx": true,
		"applySecretSyncJobQueuedTx":           true,
	},
	"internal/store/secret_sync_workload_identity.go": {
		"ApplySecretSyncWorkloadIdentitySourceUpsertedTx": true,
	},
	"internal/store/sshkey.go": {
		"ApplySSHKeyDiscoveredTx": true,
	},
}
