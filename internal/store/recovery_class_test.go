// SPDX-License-Identifier: MPL-2.0

package store

import "testing"

func TestDeploymentTargetsAreExcludedFromEventRebuildAndSnapshots(t *testing.T) {
	for _, table := range []string{"deployment_target_revisions", "deployment_targets"} {
		if containsRecoveryTable(ReadModelTables, table) {
			t.Errorf("%s is in ReadModelTables; migration 0072 legacy rows require PostgreSQL recovery", table)
		}
		if containsRecoveryTable(snapshotTables, table) {
			t.Errorf("%s is in snapshotTables; independent PostgreSQL state must not be restored by snapshots", table)
		}
	}
}

func TestMachineAuthReadModelsUseEventRecoveryAndSnapshots(t *testing.T) {
	for _, table := range []string{"machine_sessions", "machine_auth_method_overrides"} {
		if !containsRecoveryTable(ReadModelTables, table) {
			t.Errorf("%s is event-derived but missing from ReadModelTables", table)
		}
		if !containsRecoveryTable(snapshotTables, table) {
			t.Errorf("%s is event-derived but missing from snapshotTables", table)
		}
	}
	if SnapshotFormatVersion < 4 {
		t.Errorf("SnapshotFormatVersion = %d; adding machine-auth projections must invalidate older snapshots whose covered offset would skip their historical events", SnapshotFormatVersion)
	}
}

func TestOwnershipReadinessExceptionsUseEventRecoveryAndSnapshotsAUD44(t *testing.T) {
	const table = "ownership_readiness_exceptions"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is event-derived but missing from ReadModelTables", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is event-derived but missing from snapshotTables", table)
	}
	if SnapshotFormatVersion < 26 {
		t.Errorf("SnapshotFormatVersion = %d; a pre-AUD-44 snapshot cannot restore temporary ownership authority", SnapshotFormatVersion)
	}
}

func TestOwnershipAssignmentsUseEventRecoveryAndSnapshots(t *testing.T) {
	const table = "ownership_assignments"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is event-derived but missing from ReadModelTables", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is event-derived but missing from snapshotTables", table)
	}
	if SnapshotFormatVersion < 33 {
		t.Errorf("SnapshotFormatVersion = %d; a pre-v33 snapshot cannot restore asset-specific ownership decisions", SnapshotFormatVersion)
	}
}

func TestNotificationRoutingPoliciesUseEventRecoveryAndSnapshots(t *testing.T) {
	const table = "notification_routing_policies"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is event-derived but missing from ReadModelTables", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is event-derived but missing from snapshotTables", table)
	}
	if SnapshotFormatVersion < 34 {
		t.Errorf("SnapshotFormatVersion = %d; a pre-v34 snapshot cannot restore automatic notification routing authority", SnapshotFormatVersion)
	}
}

func TestWorkloadIdentityReadModelsUseEventRecoveryAndSnapshots(t *testing.T) {
	for _, table := range []string{"workload_attester_trust_sources", "secret_sync_workload_identity_sources"} {
		if !containsRecoveryTable(ReadModelTables, table) {
			t.Errorf("%s is event-derived but missing from ReadModelTables", table)
		}
		if !containsRecoveryTable(snapshotTables, table) {
			t.Errorf("%s is event-derived but missing from snapshotTables", table)
		}
	}
	if SnapshotFormatVersion < 6 {
		t.Errorf("SnapshotFormatVersion = %d; adding workload-identity projections must invalidate older snapshots", SnapshotFormatVersion)
	}
	if SnapshotFormatVersion < 7 {
		t.Errorf("SnapshotFormatVersion = %d; adding GCP workload-identity source fields must invalidate older snapshots", SnapshotFormatVersion)
	}
}

func TestTenantKeyDomainUsesEventRecoveryAndSnapshots(t *testing.T) {
	const table = "tenant_key_domains"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is event-derived but missing from ReadModelTables", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is event-derived but missing from snapshotTables", table)
	}
	if SnapshotFormatVersion < 8 {
		t.Errorf("SnapshotFormatVersion = %d; adding tenant key-domain projections must invalidate older snapshots", SnapshotFormatVersion)
	}
	if SnapshotFormatVersion < 9 {
		t.Errorf("SnapshotFormatVersion = %d; adding crypto-asset projection sequence tombstones must invalidate older snapshots", SnapshotFormatVersion)
	}
}

func TestDiscoveryFindingReplayAliasesInvalidateOlderSnapshotsAUD96(t *testing.T) {
	if SnapshotFormatVersion < 19 {
		t.Errorf("SnapshotFormatVersion = %d; discovery recorded-id aliases must invalidate older snapshots whose covered history cannot rebuild legacy triage lookup", SnapshotFormatVersion)
	}
}

func TestOutboxReconciliationConflictsUseEventRecoveryAndSnapshotsAUD97(t *testing.T) {
	const table = "outbox_reconciliation_conflicts"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is event-derived but missing from ReadModelTables", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is in the rebuild set but missing from snapshotTables; restore would hide quarantined commands", table)
	}
	if SnapshotFormatVersion < 20 {
		t.Errorf("SnapshotFormatVersion = %d; adding the AUD-97 conflict projection must invalidate older snapshots that would skip its event", SnapshotFormatVersion)
	}
}

func TestOperationApprovalsUseEventRecoveryAndSnapshotsAUD77(t *testing.T) {
	for _, table := range []string{"operation_approval_requests", "operation_approval_decisions"} {
		if !containsRecoveryTable(ReadModelTables, table) {
			t.Errorf("%s is event-derived but missing from ReadModelTables", table)
		}
		if !containsRecoveryTable(snapshotTables, table) {
			t.Errorf("%s is in the rebuild set but missing from snapshotTables; restore would erase pending approval authority", table)
		}
	}
	for _, table := range []string{"issuance_approval_requests", "issuance_approvals"} {
		if containsRecoveryTable(ReadModelTables, table) {
			t.Errorf("%s contains legacy non-event-backed rows and must remain independent PostgreSQL history", table)
		}
		if containsRecoveryTable(snapshotTables, table) {
			t.Errorf("%s is legacy PostgreSQL history and must not be restored from event-derived snapshots", table)
		}
	}
	if SnapshotFormatVersion < 21 {
		t.Errorf("SnapshotFormatVersion = %d; adding AUD-77 approval projections must invalidate older snapshots that would skip their events", SnapshotFormatVersion)
	}
}

func TestSecretSyncTargetOrderUsesEventRecoveryAndSnapshotsAUD109(t *testing.T) {
	const table = "secret_sync_jobs"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is event-derived but missing from ReadModelTables", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is event-derived but missing from snapshotTables", table)
	}
	if SnapshotFormatVersion < 21 {
		t.Errorf("SnapshotFormatVersion = %d; AUD-109 target_order cannot be recovered from a v20 payload", SnapshotFormatVersion)
	}
}

func TestPrivacyErasureOperationUsesIndependentPostgresRecovery(t *testing.T) {
	const table = "privacy_subject_erasure_operations"
	if containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is in ReadModelTables; retained-away events cannot rebuild the durable AN-5 receiver", table)
	}
	if containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is in snapshotTables; snapshot restore must not erase independent AN-5 evidence", table)
	}
}

func TestApprovedTargetFencesUseIndependentPostgresRecoveryAUD77(t *testing.T) {
	const table = "approved_target_event_fences"
	if containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is in ReadModelTables; a rebuild must preserve the append/SQL crash bridge", table)
	}
	if containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is in snapshotTables; read-model snapshots must not overwrite independent command authority", table)
	}
}

func TestSecretRotationScheduleCommandsUseIndependentPostgresRecoveryAUD106(t *testing.T) {
	const table = "secret_rotation_schedule_commands"
	if containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is in ReadModelTables; rebuild must preserve due-edge crash authority", table)
	}
	if containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is in snapshotTables; a read-model snapshot must not overwrite live command leases or receipts", table)
	}
}

func TestSecretRotationScheduleTickRowsUseIndependentPostgresRecoveryAUD113(t *testing.T) {
	const table = "secret_rotation_schedule_tick_rows"
	if containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is in ReadModelTables; rebuild must preserve immutable tick membership", table)
	}
	if containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is in snapshotTables; a read-model snapshot must not replace prepared scheduler work", table)
	}
}

func containsRecoveryTable(tables []string, want string) bool {
	for _, table := range tables {
		if table == want {
			return true
		}
	}
	return false
}

// The upstream authorization read model is event-derived, so it must be in both
// the rebuild set and the snapshot set (epic B7).
//
// Being in one but not the other is worse than being in neither: the restore
// path TRUNCATES everything in ReadModelTables and then reloads only what the
// snapshot payload carries, so a table in the first list and missing from the
// second is silently emptied by every snapshot restore. The surface would then
// report never_validated_count: 0 over an empty list — "nothing is stale" —
// which is the exact false reassurance this data exists to prevent.
func TestUpstreamAuthorizationsUseEventRecoveryAndSnapshots(t *testing.T) {
	const table = "acme_upstream_authorizations"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is event-derived but missing from ReadModelTables", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is in the truncate set but missing from snapshotTables; every snapshot "+
			"restore would erase the authorization history and then serve an empty surface", table)
	}
	if SnapshotFormatVersion < 11 {
		t.Errorf("SnapshotFormatVersion = %d; adding the upstream authorization projection must "+
			"invalidate older snapshots, whose covered offset skips every observation event and "+
			"would leave the table permanently empty while boot considers itself caught up",
			SnapshotFormatVersion)
	}
}

// The endpoint verification read model is event-derived, so it belongs in both
// the rebuild set and the snapshot set (epic D2).
//
// The failure mode of getting this wrong is specific and bad: restore
// TRUNCATES everything in ReadModelTables and reloads only what the snapshot
// payload carries, so a table in the first list and missing from the second is
// silently emptied by every restore. The console would then show an estate with
// no divergences — which is the reading an operator most wants to be true and
// the one this epic exists to stop being assumed.
func TestEndpointVerificationsUseEventRecoveryAndSnapshots(t *testing.T) {
	const table = "endpoint_verifications"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is event-derived but missing from ReadModelTables", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is in the truncate set but missing from snapshotTables; every snapshot "+
			"restore would erase the estate's verification state and show it as clean", table)
	}
	if SnapshotFormatVersion < 12 {
		t.Errorf("SnapshotFormatVersion = %d; adding the endpoint verification projection must "+
			"invalidate older snapshots, whose covered offset skips every observation event",
			SnapshotFormatVersion)
	}
}

// Every table in the truncate set must be in the reload set. The five I2/I3/I5/A5
// projections shipped in ReadModelTables without entering snapshotTables or the
// capture payload, so a snapshot restore TRUNCATED them and reloaded nothing —
// ownership conflicts, CMDB schedules, issuance requests, MDM correlations and
// upgrade campaigns all gone, while boot's covered offset skipped their events.
// This test closes the CLASS, not the instances: any future ReadModelTables
// entry missing from snapshotTables fails here by name.
func TestEveryTruncatedReadModelTableIsRestoredBySnapshots(t *testing.T) {
	for _, table := range ReadModelTables {
		if table == "tenants" {
			// The tail replay re-seeds tenants from tenant.registered events;
			// RestoreSnapshotsTx documents this exclusion.
			continue
		}
		if !containsRecoveryTable(snapshotTables, table) {
			t.Errorf("%s is truncated by snapshot restore but never reloaded; every restore "+
				"silently empties it while the covered offset skips its history", table)
		}
	}
	if SnapshotFormatVersion < 13 {
		t.Errorf("SnapshotFormatVersion = %d; adding the I2/I3/I5/A5 projections to snapshots "+
			"must invalidate older payloads that do not carry them", SnapshotFormatVersion)
	}
}

func TestRevocationEndpointHealthIsRebuiltAndSnapshotSafe(t *testing.T) {
	const table = "revocation_endpoint_health"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Fatalf("%s is event-derived but missing from the cold-rebuild truncate set", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Fatalf("%s is missing from snapshots, so restore would erase signed endpoint observations", table)
	}
	if SnapshotFormatVersion < 24 {
		t.Fatalf("SnapshotFormatVersion = %d; a v23 payload cannot restore revocation endpoint health", SnapshotFormatVersion)
	}
}

func TestMigrationRunsAreRebuiltAndSnapshotSafeAUD40(t *testing.T) {
	const table = "migration_runs"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Fatalf("%s is event-derived but missing from the cold-rebuild truncate set", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Fatalf("%s is missing from snapshots, so restore would erase paused or partial runs", table)
	}
	if SnapshotFormatVersion < 25 {
		t.Fatalf("SnapshotFormatVersion = %d; a v24 payload cannot restore migration runs", SnapshotFormatVersion)
	}
}

func TestADCSEnrollmentServicePostureIsRebuiltAndSnapshotSafeAUD37(t *testing.T) {
	const table = "adcs_enrollment_service_posture"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Fatalf("%s is event-derived but missing from the cold-rebuild truncate set", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Fatalf("%s is missing from snapshots, so restore would erase enrollment-service posture", table)
	}
	if SnapshotFormatVersion < 27 {
		t.Fatalf("SnapshotFormatVersion = %d; a v26 payload cannot restore enrollment-service posture", SnapshotFormatVersion)
	}
}

func TestAgentRevocationCachePostureInvalidatesLegacySnapshotsAUD39(t *testing.T) {
	if !containsRecoveryTable(ReadModelTables, "agents") {
		t.Fatal("agents is missing from the cold-rebuild truncate set")
	}
	if !containsRecoveryTable(snapshotTables, "agents") {
		t.Fatal("agents is missing from snapshots, so restore would erase signed revocation-cache posture")
	}
	if SnapshotFormatVersion < 28 {
		t.Fatalf("SnapshotFormatVersion = %d; a v27 payload cannot restore signed revocation-cache posture", SnapshotFormatVersion)
	}
}

func TestCMDBCIInventoryIsRebuiltAndSnapshotSafeAUD46(t *testing.T) {
	const table = "cmdb_ci_inventory"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Fatalf("%s is event-derived but missing from the cold-rebuild truncate set", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Fatalf("%s is missing from snapshots, so restore would erase an incomplete CMDB continuation", table)
	}
	if SnapshotFormatVersion < 29 {
		t.Fatalf("SnapshotFormatVersion = %d; a v28 payload cannot restore bounded CMDB sweep inventory", SnapshotFormatVersion)
	}
}

func TestTicketIntakeCheckpointIsSnapshotSafeAUD47(t *testing.T) {
	const table = "ticket_intake_schedules"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Fatalf("%s is event-derived but missing from the cold-rebuild truncate set", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Fatalf("%s is missing from snapshots, so restore would erase an incomplete ticket continuation", table)
	}
	if SnapshotFormatVersion < 30 {
		t.Fatalf("SnapshotFormatVersion = %d; a v29 payload cannot restore a bounded ticket intake sweep", SnapshotFormatVersion)
	}
}

func TestEnrollmentDiagnosticVerificationIsSnapshotSafeAUD49(t *testing.T) {
	const table = "enrollment_diagnostics"
	if !containsRecoveryTable(ReadModelTables, table) {
		t.Fatalf("%s is event-derived but missing from the cold-rebuild truncate set", table)
	}
	if !containsRecoveryTable(snapshotTables, table) {
		t.Fatalf("%s is missing from snapshots, so restore would erase the exact refusal and its prove-fixed link", table)
	}
	if SnapshotFormatVersion < 31 {
		t.Fatalf("SnapshotFormatVersion = %d; a v30 payload cannot restore AUD-49 exact refusal references or prove-fixed state", SnapshotFormatVersion)
	}
}

func TestAuditFeedCursorAndReceiptAreSnapshotSafeAUD52(t *testing.T) {
	for _, table := range []string{"audit_feed_destinations", "audit_feed_deliveries"} {
		if !containsRecoveryTable(ReadModelTables, table) {
			t.Fatalf("%s is event-derived but missing from the cold-rebuild truncate set", table)
		}
		if !containsRecoveryTable(snapshotTables, table) {
			t.Fatalf("%s is missing from snapshots, so restore would erase collector cursor or receipt evidence", table)
		}
	}
	if SnapshotFormatVersion < 32 {
		t.Fatalf("SnapshotFormatVersion = %d; a v31 payload cannot restore AUD-52 collector cursors and receipts", SnapshotFormatVersion)
	}
}
