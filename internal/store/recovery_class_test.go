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

func TestPrivacyErasureOperationUsesIndependentPostgresRecovery(t *testing.T) {
	const table = "privacy_subject_erasure_operations"
	if containsRecoveryTable(ReadModelTables, table) {
		t.Errorf("%s is in ReadModelTables; retained-away events cannot rebuild the durable AN-5 receiver", table)
	}
	if containsRecoveryTable(snapshotTables, table) {
		t.Errorf("%s is in snapshotTables; snapshot restore must not erase independent AN-5 evidence", table)
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
