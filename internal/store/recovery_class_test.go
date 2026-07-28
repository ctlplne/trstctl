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
}

func containsRecoveryTable(tables []string, want string) bool {
	for _, table := range tables {
		if table == want {
			return true
		}
	}
	return false
}
